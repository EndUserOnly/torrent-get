#include <libtorrent/session.hpp>
#include "approval_gate_client.hpp"
#include <libtorrent/session_params.hpp>
#include <libtorrent/posix_disk_io.hpp>
#include <libtorrent/settings_pack.hpp>
#include <libtorrent/add_torrent_params.hpp>
#include <libtorrent/torrent_handle.hpp>
#include <libtorrent/torrent_status.hpp>
#include <libtorrent/torrent_info.hpp>
#include <libtorrent/peer_info.hpp>
#include <libtorrent/magnet_uri.hpp>
#include <libtorrent/version.hpp>
#include <libtorrent/alert_types.hpp>
#include <libtorrent/read_resume_data.hpp>
#include <libtorrent/write_resume_data.hpp>
#include <libtorrent/error_code.hpp>
#include <libtorrent/extensions.hpp>
#include <libtorrent/peer_connection_handle.hpp>
#include <libtorrent/operations.hpp>

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/select.h>
#include <unistd.h>
#include <fcntl.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cctype>
#include <cstdint>
#include <csignal>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <limits>
#include <memory>
#include <mutex>
#include <fstream>
#include <cstdio>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

namespace lt = libtorrent;

static volatile std::sig_atomic_t g_stop = 0;

static void on_signal(int)
{
    g_stop = 1;
}

static std::string human_rate(std::int64_t bytes_per_second)
{
    static char const* units[] = {"B/s", "KiB/s", "MiB/s", "GiB/s"};
    double value = static_cast<double>(bytes_per_second);
    int unit = 0;
    while (value >= 1024.0 && unit < 3) {
        value /= 1024.0;
        ++unit;
    }

    std::ostringstream out;
    out << std::fixed << std::setprecision(unit == 0 ? 0 : 1)
        << value << ' ' << units[unit];
    return out.str();
}

static std::string clean_field(std::string value)
{
    for (char& c : value) {
        if (c == '\t' || c == '\n' || c == '\r') c = ' ';
    }
    return value;
}



// =========================================================
// SELECTIVE LIVE PEER DROP
// =========================================================
//
// Persistent deny policy remains external in nftables.
// This code only disconnects operator-selected live peers.
// =========================================================

struct selective_peer_drop_state
{
    std::mutex mutex;
    std::vector<std::string> ips;
    std::uint64_t generation = 0;

    void request(std::string const& csv)
    {
        std::vector<std::string> next;
        std::size_t start = 0;

        while (start < csv.size()) {
            std::size_t const comma = csv.find(',', start);

            std::string const ip =
                csv.substr(
                    start,
                    comma == std::string::npos
                        ? std::string::npos
                        : comma - start
                );

            if (!ip.empty()
                && std::find(next.begin(), next.end(), ip)
                    == next.end()) {
                next.push_back(ip);
            }

            if (comma == std::string::npos) break;
            start = comma + 1;
        }

        std::lock_guard<std::mutex> guard(mutex);

        ips = std::move(next);
        ++generation;

        if (generation == 0) ++generation;
    }

    bool should_drop(
        std::string const& ip,
        std::uint64_t& observed_generation
    )
    {
        std::lock_guard<std::mutex> guard(mutex);

        if (observed_generation == generation) {
            return false;
        }

        observed_generation = generation;

        return std::find(
            ips.begin(),
            ips.end(),
            ip
        ) != ips.end();
    }
};


class selective_peer_plugin final
    : public lt::peer_plugin
{
public:
    selective_peer_plugin(
        lt::peer_connection_handle peer,
        std::shared_ptr<selective_peer_drop_state> state
    )
        : peer_(std::move(peer))
        , state_(std::move(state))
    {
    }

    void tick() override
    {
        if (!state_) return;
        if (peer_.is_disconnecting()) return;

        std::string ip;

        try {
            ip = peer_.remote().address().to_string();
        }
        catch (...) {
            return;
        }

        if (!state_->should_drop(
                ip,
                observed_generation_)) {
            return;
        }

        lt::error_code const ec(
            static_cast<int>(
                lt::errors::banned_by_ip_filter
            ),
            lt::libtorrent_category()
        );

        peer_.disconnect(
            ec,
            lt::operation_t::bittorrent
        );
    }

private:
    lt::peer_connection_handle peer_;
    std::shared_ptr<selective_peer_drop_state> state_;
    std::uint64_t observed_generation_ = 0;
};


class selective_torrent_plugin final
    : public lt::torrent_plugin
{
public:
    explicit selective_torrent_plugin(
        std::shared_ptr<selective_peer_drop_state> state
    )
        : state_(std::move(state))
    {
    }

    std::shared_ptr<lt::peer_plugin>
    new_connection(
        lt::peer_connection_handle const& peer
    ) override
    {
        return std::make_shared<selective_peer_plugin>(
            peer,
            state_
        );
    }

private:
    std::shared_ptr<selective_peer_drop_state> state_;
};


// =========================================================
// METADATA SECURITY GATE
// =========================================================
//
// Complete torrent metadata is treated as untrusted input.
// Payload downloading remains disabled until this validator
// accepts the full manifest.
//
// No database.
// No metadata rewriting.
// Failure is automatic and closed.
// =========================================================

struct metadata_gate_result
{
    bool ok;
    std::string reason;
};

static metadata_gate_result metadata_reject(
    std::string const& reason
)
{
    return metadata_gate_result{false, reason};
}

static metadata_gate_result validate_torrent_metadata(
    std::shared_ptr<lt::torrent_info const> const& ti
)
{
    if (!ti) {
        return metadata_reject(
            "metadata unavailable"
        );
    }

    auto const& files=ti->files();

    int const count=files.num_files();

    if (count <= 0) {
        return metadata_reject(
            "empty manifest"
        );
    }

    // Resource-abuse ceilings, not ordinary content limits.
    constexpr int max_files=250000;
    constexpr std::size_t max_path=4096;
    constexpr std::size_t max_component=255;
    constexpr std::size_t max_depth=128;

    if (count > max_files) {
        return metadata_reject(
            "excessive file count"
        );
    }

    std::set<std::string> file_paths;
    std::set<std::string> directory_paths;

    std::int64_t summed_size=0;

    for (int i=0; i<count; ++i) {

        lt::file_index_t const index{i};

        if (files.file_absolute_path(index)) {
            return metadata_reject(
                "absolute payload path"
            );
        }

        auto const flags=files.file_flags(index);

        if (
            (flags & lt::file_storage::flag_symlink)
            != lt::file_flags_t{}
        ) {
            return metadata_reject(
                "symlink entry"
            );
        }

        std::string const raw=files.file_path(index);

        if (raw.empty()) {
            return metadata_reject(
                "empty payload path"
            );
        }

        if (raw.size() > max_path) {
            return metadata_reject(
                "payload path too long"
            );
        }

        if (
            raw.front()=='/'
            || raw.front()=='\\'
        ) {
            return metadata_reject(
                "absolute-like payload path"
            );
        }

        // torrent-get accepts only canonical '/' path separators.
        if (raw.find('\\') != std::string::npos) {
            return metadata_reject(
                "non-canonical path separator"
            );
        }

        for (unsigned char const c : raw) {
            if (
                c == 0
                || c < 0x20
                || c == 0x7f
            ) {
                return metadata_reject(
                    "control character in path"
                );
            }
        }

        std::vector<std::string> parts;
        std::string part;

        for (char const c : raw) {
            if (c=='/') {

                if (part.empty()) {
                    return metadata_reject(
                        "empty path component"
                    );
                }

                parts.push_back(part);
                part.clear();
            }
            else {
                part.push_back(c);
            }
        }

        if (part.empty()) {
            return metadata_reject(
                "empty final path component"
            );
        }

        parts.push_back(part);

        if (parts.size() > max_depth) {
            return metadata_reject(
                "payload path depth exceeded"
            );
        }

        for (auto const& component : parts) {

            if (
                component=="."
                || component==".."
            ) {
                return metadata_reject(
                    "unsafe path component"
                );
            }

            if (component.size() > max_component) {
                return metadata_reject(
                    "path component too long"
                );
            }
        }

        std::string normalized;

        for (std::size_t n=0; n<parts.size(); ++n) {
            if (n != 0) normalized.push_back('/');
            normalized += parts[n];
        }

        if (!file_paths.insert(normalized).second) {
            return metadata_reject(
                "duplicate normalized path"
            );
        }

        // A previously seen directory cannot later become a file.
        if (
            directory_paths.find(normalized)
            != directory_paths.end()
        ) {
            return metadata_reject(
                "directory-file path conflict"
            );
        }

        std::string prefix;

        for (
            std::size_t n=0;
            n + 1 < parts.size();
            ++n
        ) {
            if (!prefix.empty()) {
                prefix.push_back('/');
            }

            prefix += parts[n];

            // A previously seen file cannot become a parent directory.
            if (
                file_paths.find(prefix)
                != file_paths.end()
            ) {
                return metadata_reject(
                    "file-directory path conflict"
                );
            }

            directory_paths.insert(prefix);
        }

        std::int64_t const size=
            files.file_size(index);

        if (size < 0) {
            return metadata_reject(
                "negative file size"
            );
        }

        if (
            summed_size >
            std::numeric_limits<std::int64_t>::max()
            - size
        ) {
            return metadata_reject(
                "manifest size overflow"
            );
        }

        summed_size += size;
    }

    if (summed_size != ti->total_size()) {
        return metadata_reject(
            "declared size inconsistent"
        );
    }

    if (ti->piece_length() <= 0) {
        return metadata_reject(
            "invalid piece length"
        );
    }

    return metadata_gate_result{true, ""};
}




static std::string peer_have_percent(lt::peer_info const& p)
{
    if (p.flags & lt::peer_info::seed) return "100.0";

    if (p.pieces.size() == 0) return "?";

    std::size_t have = 0;
    for (std::size_t i = 0; i < p.pieces.size(); ++i) {
        if (p.pieces[i]) ++have;
    }

    double pct = (100.0 * static_cast<double>(have))
        / static_cast<double>(p.pieces.size());

    std::ostringstream out;
    out << std::fixed << std::setprecision(1) << pct;
    return out.str();
}

static bool same_user_peer(int fd)
{
#ifdef SO_PEERCRED
    struct ucred cred{};
    socklen_t len = sizeof(cred);
    if (::getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cred, &len) != 0) return false;
    return cred.uid == ::getuid();
#else
    return true;
#endif
}

static bool read_strict_command(int fd, std::string& cmd)
{
    constexpr std::size_t max_command = 4096;
    cmd.clear();

    timeval timeout{};
    timeout.tv_sec = 2;
    timeout.tv_usec = 0;
    ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

    bool terminated = false;
    while (!terminated && cmd.size() <= max_command) {
        char buf[64];
        ssize_t const n = ::recv(fd, buf, sizeof(buf), 0);
        if (n <= 0) return false;

        for (ssize_t i = 0; i < n; ++i) {
            unsigned char const c = static_cast<unsigned char>(buf[i]);
            if (c == '\n') {
                if (terminated || i != n - 1) return false; // one command only
                terminated = true;
                break;
            }
            if (c == '\r') {
                if (i != n - 2 || buf[i + 1] != '\n') return false;
                continue;
            }
            if (c < 0x20 || c > 0x7e) return false;
            cmd.push_back(static_cast<char>(c));
            if (cmd.size() > max_command) return false;
        }
    }

    if (!terminated || cmd.empty()) return false;
    if (cmd.front() == ' ' || cmd.back() == ' ') return false;
    return true;
}

enum class control_command { status, peers, files, drop_peers, sequence, limit_down, limit_up, limits, invalid };

static control_command parse_control_command(std::string const& cmd, std::string& arg)
{
    arg.clear();
    if (cmd == "STATUS") return control_command::status;
    if (cmd == "PEERS") return control_command::peers;
    if (cmd == "FILES") return control_command::files;
    if (cmd.rfind("DROPPEERS ", 0) == 0) {
        arg = cmd.substr(std::string("DROPPEERS ").size());

        if (arg.empty()
            || arg.front() == ','
            || arg.back() == ',') {
            arg.clear();
            return control_command::invalid;
        }

        for (char const ch : arg) {
            bool const valid =
                (ch >= '0' && ch <= '9')
                || (ch >= 'a' && ch <= 'f')
                || (ch >= 'A' && ch <= 'F')
                || ch == '.'
                || ch == ':'
                || ch == ',';

            if (!valid) {
                arg.clear();
                return control_command::invalid;
            }
        }

        return control_command::drop_peers;
    }
    if (cmd == "LIMITS") return control_command::limits;

    auto parse_rate_arg = [&](char const* prefix, control_command type) {
        std::string const p(prefix);
        if (cmd.rfind(p, 0) != 0) return control_command::invalid;

        arg = cmd.substr(p.size());

        if (arg.empty()) {
            arg.clear();
            return control_command::invalid;
        }

        for (char const c : arg) {
            if (c < '0' || c > '9') {
                arg.clear();
                return control_command::invalid;
            }
        }

        return type;
    };

    if (cmd.rfind("LIMIT DOWN ", 0) == 0)
        return parse_rate_arg("LIMIT DOWN ", control_command::limit_down);

    if (cmd.rfind("LIMIT UP ", 0) == 0)
        return parse_rate_arg("LIMIT UP ", control_command::limit_up);

    if (cmd.rfind("SEQUENCE ", 0) == 0) {
        arg = cmd.substr(std::string("SEQUENCE ").size());

        if (arg.empty()
            || arg.front() == ','
            || arg.back() == ',') {
            arg.clear();
            return control_command::invalid;
        }

        for (char const ch : arg) {
            if ((ch < '0' || ch > '9') && ch != ',') {
                arg.clear();
                return control_command::invalid;
            }
        }

        return control_command::sequence;
    }

    return control_command::invalid;
}

static void write_all(int fd, std::string const& data)
{
    char const* p = data.data();
    std::size_t left = data.size();

    while (left > 0) {
        ssize_t const n = ::send(fd, p, left, MSG_NOSIGNAL);
        if (n <= 0) return;
        p += n;
        left -= static_cast<std::size_t>(n);
    }
}

static void control_server(
    lt::session& session,
    lt::torrent_handle handle,
    std::string socket_path,
    std::atomic<bool>& metadata_gate_passed,
    std::shared_ptr<selective_peer_drop_state> peer_drop_state)
{
    int server = ::socket(AF_UNIX, SOCK_STREAM, 0);
    if (server < 0) return;

    ::unlink(socket_path.c_str());

    sockaddr_un addr{};
    addr.sun_family = AF_UNIX;

    if (socket_path.size() >= sizeof(addr.sun_path)) {
        ::close(server);
        return;
    }

    std::strncpy(addr.sun_path, socket_path.c_str(), sizeof(addr.sun_path) - 1);

    if (::bind(server, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
        ::close(server);
        return;
    }

    ::chmod(socket_path.c_str(), 0600);

    if (::listen(server, 4) != 0) {
        ::unlink(socket_path.c_str());
        ::close(server);
        return;
    }

    // Operator-defined logical file sequence.
    //
    // This state is deliberately owned by the existing worker control
    // thread. No wrapper, helper process, or external sequencer exists.
    std::vector<int> sequence_order;
    std::size_t sequence_position = 0;
    bool sequence_active = false;

    auto apply_sequence_position = [&]() -> bool {
        auto const ti = handle.torrent_file();

        if (!ti
            || sequence_position >= sequence_order.size()
            || !metadata_gate_passed.load()) {
            return false;
        }

        int const count = ti->files().num_files();
        int const selected = sequence_order[sequence_position];

        if (selected < 0 || selected >= count) {
            sequence_active = false;
            return false;
        }

        std::vector<lt::download_priority_t> priorities(
            static_cast<std::size_t>(count),
            lt::download_priority_t{0}
        );

        priorities[static_cast<std::size_t>(selected)] =
            lt::download_priority_t{7};

        handle.prioritize_files(priorities);
        return true;
    };

    while (!g_stop) {
        // Advance automatically when the currently selected file is
        // verified complete. Only one file is wanted at any moment.
        if (sequence_active && metadata_gate_passed.load()) {
            auto const ti = handle.torrent_file();

            if (ti) {
                auto const progress =
                    handle.file_progress(
                        lt::torrent_handle::piece_granularity
                    );

                bool advanced = false;

                while (sequence_position < sequence_order.size()) {
                    int const index_value =
                        sequence_order[sequence_position];

                    if (index_value < 0
                        || index_value >= ti->files().num_files()) {
                        sequence_active = false;
                        break;
                    }

                    lt::file_index_t const index{index_value};

                    std::int64_t const size =
                        ti->files().file_size(index);

                    std::int64_t const done =
                        static_cast<std::size_t>(index_value)
                                < progress.size()
                            ? progress[
                                static_cast<std::size_t>(
                                    index_value
                                )
                              ]
                            : 0;

                    if (done < size)
                        break;

                    ++sequence_position;
                    advanced = true;
                }

                if (sequence_position >= sequence_order.size()) {
                    sequence_active = false;
                }
                else if (advanced) {
                    apply_sequence_position();
                }
                else {
                    // Handles a sequence submitted before the metadata
                    // approval gate completed.
                    apply_sequence_position();
                }
            }
        }

        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(server, &readfds);

        timeval tv{};
        tv.tv_sec = 0;
        tv.tv_usec = 250000;

        int const ready = ::select(server + 1, &readfds, nullptr, nullptr, &tv);
        if (ready <= 0) continue;

        int client = ::accept(server, nullptr, nullptr);
        if (client < 0) continue;

        if (!same_user_peer(client)) {
            write_all(client, "ERROR\tunauthorized local client\n");
            ::close(client);
            continue;
        }

        std::string cmd;
        if (!read_strict_command(client, cmd)) {
            write_all(client, "ERROR\tmalformed command\n");
            ::close(client);
            continue;
        }

        std::string arg;
        control_command const command = parse_control_command(cmd, arg);

        if (command == control_command::status) {
            lt::torrent_status st = handle.status();

            std::int64_t total_size = 0;
            std::int64_t total_done = 0;
            double whole_progress = 0.0;

            auto const ti = handle.torrent_file();
            bool const metadata = ti != nullptr;

            if (metadata) {
                total_size = ti->total_size();

                auto const file_progress =
                    handle.file_progress(
                        lt::torrent_handle::piece_granularity
                    );

                for (std::int64_t const done : file_progress) {
                    if (done > 0)
                        total_done += done;
                }

                if (total_done > total_size)
                    total_done = total_size;

                whole_progress =
                    total_size > 0
                    ? static_cast<double>(total_done)
                        / static_cast<double>(total_size)
                    : 1.0;
            }

            std::ostringstream out;
            out << "STATUS"
                << '\t' << (metadata ? 1 : 0)
                << '\t' << std::fixed << std::setprecision(6)
                << whole_progress
                << '\t' << total_size
                << '\t' << st.download_payload_rate
                << '\t' << st.upload_payload_rate
                << '\t' << st.num_peers
                << '\t' << st.num_seeds
                << '\t' << clean_field(st.name)
                << '\t' << st.download_rate
                << '\t' << st.upload_rate
                << '\n';
            write_all(client, out.str());
        }
        else if (command == control_command::peers) {
            std::vector<lt::peer_info> peers;
            handle.get_peer_info(peers);

            std::ostringstream out;
            out << "PEERS\t" << peers.size() << '\n';

            for (lt::peer_info const& p : peers) {
                std::string ip = "?";
                int port = 0;
                try {
                    ip = p.ip.address().to_string();
                    port = p.ip.port();
                } catch (...) {}

                bool const seed = bool(p.flags & lt::peer_info::seed);
                bool const interesting = bool(p.flags & lt::peer_info::interesting);
                bool const choked = bool(p.flags & lt::peer_info::remote_choked);
                bool const handshake = bool(p.flags & lt::peer_info::handshake);
                bool const connecting = bool(p.flags & lt::peer_info::connecting);

                std::string state;
                if (connecting) state = "connecting";
                else if (handshake) state = "handshake";
                else if (choked) state = "choked";
                else if (seed) state = "complete";
                else state = "peer";

                out << "PEER"
                    << '\t' << clean_field(ip)
                    << '\t' << port
                    << '\t' << clean_field(p.client.empty() ? "?" : p.client)
                    << '\t' << p.payload_down_speed
                    << '\t' << p.payload_up_speed
                    << '\t' << (seed ? 1 : 0)
                    << '\t' << peer_have_percent(p)
                    << '\t' << (interesting ? 1 : 0)
                    << '\t' << clean_field(state)
                    << '\t' << 0
                    << '\t' << p.down_speed
                    << '\t' << p.up_speed
                    << '\t' << p.total_download
                    << '\t' << p.total_upload
                    << '\n';
            }

            write_all(client, out.str());
        }
        else if (command == control_command::drop_peers) {
            if (!peer_drop_state) {
                write_all(
                    client,
                    "ERROR\tselective peer drop unavailable\n"
                );
            }
            else {
                peer_drop_state->request(arg);
                write_all(client, "OK\tQUEUED\tPEERS\n");
            }
        }
        else if (command == control_command::limit_down) {
            try {
                long long const value = std::stoll(arg);

                if (value < 0 || value > 2147483647LL) {
                    write_all(client, "ERROR\tinvalid download limit\n");
                } else {
                    handle.set_download_limit(static_cast<int>(value));

                    write_all(
                        client,
                        "OK\tLIMIT\tDOWN\t"
                        + std::to_string(value)
                        + "\n"
                    );
                }
            }
            catch (...) {
                write_all(client, "ERROR\tinvalid download limit\n");
            }
        }
        else if (command == control_command::limit_up) {
            try {
                long long const value = std::stoll(arg);

                if (value < 0 || value > 2147483647LL) {
                    write_all(client, "ERROR\tinvalid upload limit\n");
                } else {
                    handle.set_upload_limit(static_cast<int>(value));

                    write_all(
                        client,
                        "OK\tLIMIT\tUP\t"
                        + std::to_string(value)
                        + "\n"
                    );
                }
            }
            catch (...) {
                write_all(client, "ERROR\tinvalid upload limit\n");
            }
        }
        else if (command == control_command::sequence) {
            auto const ti = handle.torrent_file();

            if (!ti) {
                write_all(
                    client,
                    "ERROR\tmetadata unavailable\n"
                );
            } else {
                bool digits =
                    !arg.empty()
                    && std::all_of(
                        arg.begin(),
                        arg.end(),
                        [](unsigned char c) {
                            return c >= '0' && c <= '9';
                        }
                    );

                if (!digits) {
                    write_all(
                        client,
                        "ERROR\tinvalid file priority index\n"
                    );
                } else {
                    try {
                        long long const raw =
                            std::stoll(arg);

                        int const count =
                            ti->files().num_files();

                        if (
                            raw < 0
                            || raw >= count
                        ) {
                            write_all(
                                client,
                                "ERROR\tfile priority index out of range\n"
                            );
                        } else {
                            std::vector<
                                lt::download_priority_t
                            > priorities(
                                static_cast<std::size_t>(
                                    count
                                ),
                                lt::default_priority
                            );

                            priorities[
                                static_cast<std::size_t>(
                                    raw
                                )
                            ] = lt::top_priority;

                            handle.prioritize_files(
                                priorities
                            );

                            write_all(
                                client,
                                "OK\tPRIORITY\t"
                                + std::to_string(raw)
                                + "\t7\n"
                            );
                        }
                    }
                    catch (...) {
                        write_all(
                            client,
                            "ERROR\tinvalid file priority index\n"
                        );
                    }
                }
            }
        }
        else if (command == control_command::limits) {
            std::ostringstream out;

            out << "LIMITS"
                << '\t' << handle.download_limit()
                << '\t' << handle.upload_limit()
                << '\n';

            write_all(client, out.str());
        }
        else if (command == control_command::files) {
            auto const ti = handle.torrent_file();
            if (!ti) {
                write_all(client, "ERROR\tmetadata unavailable\n");
            } else {
                auto const progress = handle.file_progress(lt::torrent_handle::piece_granularity);
                auto const& files = ti->files();
                std::ostringstream out;
                out << "FILES\t" << files.num_files() << '\n';
                for (int i = 0; i < files.num_files(); ++i) {
                    lt::file_index_t const index{i};
                    std::int64_t const size = files.file_size(index);
                    std::int64_t const done = i < static_cast<int>(progress.size()) ? progress[static_cast<std::size_t>(i)] : 0;
                    out << "FILE"
                        << '\t' << size
                        << '\t' << done
                        << '\t' << clean_field(files.file_path(index))
                        << '\n';
                }
                write_all(client, out.str());
            }
        }
        else {
            write_all(client, "ERROR\tmalformed or unsupported command\n");
        }

        ::close(client);
    }

    ::unlink(socket_path.c_str());
    ::close(server);
}

static std::vector<char> read_binary_file(std::string const& path)
{
    std::ifstream in(path, std::ios::binary);

    if (!in) return {};

    in.seekg(0, std::ios::end);
    std::streamsize const size = in.tellg();

    if (size <= 0) return {};

    in.seekg(0, std::ios::beg);

    std::vector<char> data(static_cast<std::size_t>(size));
    in.read(data.data(), size);

    if (!in) return {};

    return data;
}

static bool write_resume_atomic(
    std::string const& path,
    lt::add_torrent_params const& params)
{
    try {
        std::vector<char> const data =
            lt::write_resume_data_buf(params);

        std::string const tmp =
            path + ".tmp." + std::to_string(::getpid());

        int const fd = ::open(
            tmp.c_str(),
            O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC,
            0600
        );

        if (fd < 0) {
            std::cerr
                << "\nResume warning: unable to open temporary state file.\n";
            return false;
        }

        std::size_t written = 0;
        while (written < data.size()) {
            ssize_t const count = ::write(
                fd,
                data.data() + written,
                data.size() - written
            );
            if (count <= 0) {
                ::close(fd);
                ::unlink(tmp.c_str());
                std::cerr << "\nResume warning: state write failed.\n";
                return false;
            }
            written += static_cast<std::size_t>(count);
        }

        bool const sync_failed = ::fsync(fd) != 0;
        bool const close_failed = ::close(fd) != 0;
        if (sync_failed || close_failed) {
            ::unlink(tmp.c_str());
            std::cerr << "\nResume warning: state fsync failed.\n";
            return false;
        }

        std::string const previous = path + ".prev";
        bool const had_current = ::access(path.c_str(), F_OK) == 0;
        if (had_current && ::rename(path.c_str(), previous.c_str()) != 0) {
            ::unlink(tmp.c_str());
            std::cerr << "\nResume warning: previous generation rotation failed.\n";
            return false;
        }

        if (::rename(tmp.c_str(), path.c_str()) != 0) {
            if (had_current) ::rename(previous.c_str(), path.c_str());
            std::cerr
                << "\nResume warning: atomic state replacement failed.\n";
            ::unlink(tmp.c_str());
            return false;
        }

        std::string const directory = path.substr(0, path.find_last_of('/'));
        int const dirfd = ::open(directory.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        if (dirfd < 0 || ::fsync(dirfd) != 0) {
            if (dirfd >= 0) ::close(dirfd);
            std::cerr << "\nResume warning: directory fsync failed.\n";
            return false;
        }
        ::close(dirfd);

        return true;
    }
    catch (std::exception const& e) {
        std::cerr
            << "\nResume warning: "
            << e.what()
            << '\n';
        return false;
    }
}

static void drain_resume_alerts(
    lt::session& session,
    std::string const& resume_path,
    int& pending,
    bool& write_failed)
{
    std::vector<lt::alert*> alerts;
    session.pop_alerts(&alerts);

    for (lt::alert const* alert : alerts) {
        if (auto const* rd =
                lt::alert_cast<lt::save_resume_data_alert>(alert)) {

            if (write_resume_atomic(resume_path, rd->params)) {
                std::cout
                    << "\nResume state saved.\n";
            }
            else {
                write_failed = true;
            }

            if (pending > 0) --pending;
            continue;
        }

        if (auto const* failed =
                lt::alert_cast<lt::save_resume_data_failed_alert>(alert)) {

            if (failed->error !=
                lt::errors::resume_data_not_modified) {

                std::cerr
                    << "\nResume warning: "
                    << failed->error.message()
                    << '\n';
                write_failed = true;
            }

            if (pending > 0) --pending;
        }
    }
}


int main(int argc, char* argv[])
{
    if (argc != 6) {
        std::cerr
            << "Usage:\n"
            << "  torrent-worker-posix '<source>' <save-path> <job-id> <resume-file> <worker-nonce>\n"
            << "  source: magnet URI or absolute .torrent path\n";
        return 2;
    }

    std::signal(SIGINT, on_signal);
    std::signal(SIGTERM, on_signal);
    std::signal(SIGPIPE, SIG_IGN);

    std::string const source = argv[1];
    std::string const save_path = argv[2];
    std::string const job_id = argv[3];
    std::string const resume_path = argv[4];
    std::string const worker_nonce = argv[5];

    if (job_id.empty() || job_id.size() > 20) {
        std::cerr << "Invalid job ID.\n";
        return 2;
    }

    for (char const c : job_id) {
        if (!std::isdigit(static_cast<unsigned char>(c))) {
            std::cerr << "Invalid job ID.\n";
            return 2;
        }
    }

    if (worker_nonce.size() < 32 || worker_nonce.size() > 128) {
        std::cerr << "Invalid worker nonce.\n";
        return 2;
    }

    try {
        std::cout << "libtorrent: " << lt::version() << '\n';
        std::cout << "PID:        " << ::getpid() << '\n';
        std::cout << "Save path:  " << save_path << '\n';
        std::cout << "Engine:     native C++, one libtorrent session\n";
        std::cout << "Disk I/O:   POSIX backend (no mmap)\n";
        std::cout << "Peer IPC:   local-only; NFT peer policy external\n\n";

        lt::settings_pack settings;
        settings.set_bool(lt::settings_pack::enable_dht, true);
        settings.set_bool(lt::settings_pack::enable_lsd, true);
        settings.set_bool(lt::settings_pack::enable_upnp, true);
        settings.set_bool(lt::settings_pack::enable_natpmp, true);
        settings.set_bool(lt::settings_pack::announce_to_all_trackers, true);
        settings.set_bool(lt::settings_pack::announce_to_all_tiers, true);

        // torrent-get Volume 1.0 stable release identity.
        // Sent to trackers and compatible BitTorrent peers.
        settings.set_str(
            lt::settings_pack::peer_fingerprint,
            "-TG1000-"
        );
        settings.set_str(
            lt::settings_pack::user_agent,
            std::string("torrent-get/1.0 libtorrent/") + lt::version()
        );
        settings.set_str(
            lt::settings_pack::handshake_client_version,
            "torrent-get v1.0"
        );

        // Startup peer acquisition:
        // libtorrent default torrent_connect_boost is 30.
        // Moderate soak-test increase to accelerate initial peer connections.
        settings.set_int(
            lt::settings_pack::torrent_connect_boost,
            60
        );

        lt::session_params session_params(settings);
        session_params.disk_io_constructor = lt::posix_disk_io_constructor;

        lt::session session(std::move(session_params));

        // Native source ingestion.
        //
        // Magnets use libtorrent's magnet parser.
        // .torrent files enter directly as torrent_info; they are
        // never converted into magnets.
        bool const source_is_magnet =
            source.rfind("magnet:?", 0) == 0;

        lt::add_torrent_params expected;
        lt::add_torrent_params params;

        if (source_is_magnet) {
            expected = lt::parse_magnet_uri(source);
            params = expected;
        }
        else {
            if (source.empty() || source.front() != '/') {
                throw std::runtime_error(
                    "torrent source must be an absolute path"
                );
            }

            if (
                source.size() < 8
                || source.substr(source.size()-8) != ".torrent"
            ) {
                throw std::runtime_error(
                    "torrent source must end in .torrent"
                );
            }

            lt::error_code ec;

            auto ti =
                std::make_shared<lt::torrent_info>(
                    source,
                    ec
                );

            if (ec || !ti) {
                throw std::runtime_error(
                    "unable to read torrent file: "
                    + ec.message()
                );
            }

            expected.ti = ti;
            expected.info_hashes = ti->info_hashes();

            params = expected;
        }

        bool loaded_resume = false;

        for (std::string const& candidate : {
                 resume_path,
                 resume_path + ".prev"
             }) {
            std::vector<char> const resume_data =
                read_binary_file(candidate);
            if (resume_data.empty()) continue;

            lt::error_code ec;
            lt::add_torrent_params restored =
                lt::read_resume_data(resume_data, ec);

            if (!ec && restored.info_hashes == expected.info_hashes) {
                params = std::move(restored);
                loaded_resume = true;
                std::cout
                    << "Resume:     local fastresume loaded"
                    << (candidate == resume_path ? "\n" : " (previous generation)\n");
                break;
            }

            std::cerr
                << "Resume warning: rejected " << candidate << "\n";
        }

        if (!loaded_resume) {
            std::cout
                << "Resume:     no local fastresume; source bootstrap\n";
        }

        // Never trust a persisted resume file to select the destination.
        params.save_path = save_path;

        // Native libtorrent sequential piece selection.
        //
        // Apply this AFTER magnet/fastresume selection is finalized so a
        // restored add_torrent_params object cannot overwrite the policy.
        // Preserve every other torrent flag already present in params.
        params.flags |= lt::torrent_flags::sequential_download;

        // -----------------------------------------------------
        // METADATA SECURITY GATE
        //
        // Every start, including a trusted local fastresume,
        // passes through the same manifest validator.
        //
        // upload_mode prevents payload piece requests.
        // default_dont_download keeps source-discovered files
        // priority 0 until explicitly approved.
        // auto_managed is removed so libtorrent cannot release
        // upload_mode independently.
        // -----------------------------------------------------
        params.flags |= lt::torrent_flags::upload_mode;
        params.flags |= lt::torrent_flags::default_dont_download;

        // torrent-get owns the security transition manually.
        //
        // Clearing auto_managed prevents libtorrent from releasing
        // upload_mode independently. Because normal default/resume
        // state may also carry paused, explicitly clear paused so
        // tracker/DHT/peer metadata discovery remains active.
        params.flags &= ~lt::torrent_flags::auto_managed;
        params.flags &= ~lt::torrent_flags::paused;

        auto peer_drop_state =
            std::make_shared<selective_peer_drop_state>();

        params.extensions.emplace_back(
            [peer_drop_state](
                lt::torrent_handle const&,
                lt::client_data_t
            ) -> std::shared_ptr<lt::torrent_plugin>
            {
                return std::make_shared<
                    selective_torrent_plugin
                >(peer_drop_state);
            }
        );

        lt::torrent_handle handle =
            session.add_torrent(std::move(params));

        int pending_resume_saves = 0;
        bool resume_write_failed = false;

        // A valid fastresume generated by torrent-get already carries
        // the info dictionary. Do not rewrite it merely because the
        // worker restarted.
        bool metadata_save_requested = loaded_resume;
        auto next_periodic_resume =
            std::chrono::steady_clock::now() + std::chrono::seconds(30);

        std::string const socket_path =
            "/run/user/" + std::to_string(::getuid())
            + "/torrent-get/torrent-worker-job-" + job_id + ".sock";

        std::atomic<bool> metadata_gate_passed_shared{false};

        std::thread control(
            control_server,
            std::ref(session),
            handle,
            socket_path,
            std::ref(metadata_gate_passed_shared),
            peer_drop_state
        );

    auto const metadata_deadline =
        std::chrono::steady_clock::now() + std::chrono::minutes(5);

        bool metadata_gate_passed = false;

        while (!g_stop) {
            lt::torrent_status st = handle.status();

            bool const metadata = handle.torrent_file() != nullptr;

            if (metadata && !metadata_gate_passed) {

                auto const ti=handle.torrent_file();

                metadata_gate_result const gate=
                    validate_torrent_metadata(ti);

                if (!gate.ok) {
                    std::cerr
                        << "\nMETADATA REJECTED — "
                        << gate.reason
                        << "\n";

                    // Fail closed. Payload download has never been
                    // released from upload_mode / dont_download.
                    handle.pause();
                    g_stop=1;
                    break;
                }

                // -------------------------------------------------
                // APPROVAL PERSISTENCE GATE
                //
                // The existing metadata validator above remains the
                // admission authority for metadata structure.
                //
                // Persistence must succeed before payload priorities
                // are released.
                // -------------------------------------------------
                if (!torrent_get::approval::admit(
                    ti,
                    source,
                    job_id
                )) {
                    std::cerr
                        << "\nMETADATA APPROVAL DENIED\n";

                    handle.pause();
                    g_stop=1;
                    break;
                }

                // Release the exact validated manifest.
                std::vector<lt::download_priority_t> priorities(
                    static_cast<std::size_t>(
                        ti->files().num_files()
                    ),
                    lt::default_priority
                );

                handle.prioritize_files(priorities);

                handle.unset_flags(
                    lt::torrent_flags::upload_mode
                );

                metadata_gate_passed=true;
                metadata_gate_passed_shared.store(true);

                std::cerr
                    << "\nMETADATA ACCEPTED — "
                    << ti->files().num_files()
                    << " file(s), "
                    << ti->total_size()
                    << " bytes\n";
            }

            // Drain responses to explicitly requested resume saves.
            // save_resume_data alerts are non-discardable.
            drain_resume_alerts(
                session,
                resume_path,
                pending_resume_saves,
                resume_write_failed
            );

            // First successful source metadata acquisition is persisted
            // immediately. This is one event-driven write, not a timer.
            if (metadata && !metadata_save_requested) {
                handle.save_resume_data(
                    lt::torrent_handle::save_info_dict
                );

                ++pending_resume_saves;
                metadata_save_requested = true;
            }

            if (metadata && pending_resume_saves == 0 &&
                std::chrono::steady_clock::now() >= next_periodic_resume) {
                handle.save_resume_data(
                    lt::torrent_handle::only_if_modified
                    | lt::torrent_handle::save_info_dict
                );
                ++pending_resume_saves;
                next_periodic_resume =
                    std::chrono::steady_clock::now() + std::chrono::seconds(30);
            }

        if (!metadata &&
            std::chrono::steady_clock::now() >= metadata_deadline) {
            std::cerr
                << "\nORPHANED: metadata unavailable after 5 minutes.\n";
            g_stop = 1;
            break;
        }

        std::string name = st.name.empty() ? "fetching metadata" : st.name;
            if (name.size() > 27) name.resize(27);

            std::cout
                << '\r'
                << std::left << std::setw(28) << name
                << " | "
                << std::right << std::fixed << std::setprecision(1)
                << std::setw(6) << (st.progress * 100.0f) << "%"
                << " | down " << std::setw(11) << human_rate(st.download_payload_rate)
                << " | up "   << std::setw(11) << human_rate(st.upload_payload_rate)
                << " | peers " << std::setw(4) << st.num_peers
                << " | seeds " << std::setw(4) << st.num_seeds
                << "      "
                << std::flush;

            std::this_thread::sleep_for(std::chrono::seconds(1));
        }

        // Quiesce transfer activity before capturing final state.
        if (handle.is_valid()) handle.pause();

        // Capture piece/block state on every orderly stop.
        drain_resume_alerts(
            session,
            resume_path,
            pending_resume_saves,
            resume_write_failed
        );

        if (handle.is_valid() &&
            handle.torrent_file() != nullptr) {

            handle.save_resume_data(
                lt::torrent_handle::save_info_dict
            );

            ++pending_resume_saves;

            auto const resume_deadline =
                std::chrono::steady_clock::now()
                + std::chrono::seconds(3);

            while (pending_resume_saves > 0 &&
                   std::chrono::steady_clock::now()
                       < resume_deadline) {

                session.wait_for_alert(
                    std::chrono::milliseconds(100)
                );

                drain_resume_alerts(
                    session,
                    resume_path,
                    pending_resume_saves,
                    resume_write_failed
                );
            }

            if (pending_resume_saves > 0) {
                std::cerr
                    << "\nResume warning: save response timed out.\n";
                resume_write_failed = true;
            }
        }

        if (resume_write_failed) {
            std::cerr << "\nTorrent stopped without a confirmed final checkpoint.\n";
        }
        else {
            std::cout << "\nTorrent stopped cleanly.\n";
        }

        if (control.joinable()) control.join();

        try {
            session.remove_torrent(handle);
        } catch (...) {
        }

        return resume_write_failed ? 3 : 0;
    }
    catch (std::exception const& e) {
        std::cerr << "\nError: " << e.what() << '\n';
        return 1;
    }
}
