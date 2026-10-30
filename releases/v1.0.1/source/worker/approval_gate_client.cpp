#include "approval_gate_client.hpp"

#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cerrno>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <string>


namespace lt = libtorrent;


namespace torrent_get::approval
{

static std::string hex_encode(
    std::string const& value
)
{
    static char const hex[] =
        "0123456789abcdef";

    std::string result;

    result.reserve(
        value.size() * 2
    );

    for (
        unsigned char const c
        : value
    )
    {
        result.push_back(
            hex[(c >> 4) & 0x0f]
        );

        result.push_back(
            hex[c & 0x0f]
        );
    }

    return result;
}


bool admit(
    std::shared_ptr<
        lt::torrent_info const
    > const& ti,
    std::string const& magnet,
    std::string const& job_id
)
{
    if (!ti)
        return false;

    std::string const base =
        "/run/user/"
        + std::to_string(
            static_cast<unsigned long>(
                ::getuid()
            )
        )
        + "/torrent-get/security";

    std::string const stem =
        base
        + "/approval-job-"
        + job_id
        + "-"
        + std::to_string(
            static_cast<unsigned long>(
                ::getpid()
            )
        );

    std::string const info_path =
        stem + ".info";

    std::string const manifest_path =
        stem + ".manifest";

    std::string const magnet_path =
        stem + ".magnet";

    auto cleanup = [&]()
    {
        ::unlink(
            info_path.c_str()
        );

        ::unlink(
            manifest_path.c_str()
        );

        ::unlink(
            magnet_path.c_str()
        );
    };

    try
    {
        auto const info =
            ti->info_section();

        if (info.empty())
            return false;

        {
            std::ofstream out(
                info_path,
                std::ios::binary
                | std::ios::trunc
            );

            if (!out)
                return false;

            out.write(
                info.data(),
                static_cast<
                    std::streamsize
                >(info.size())
            );

            out.flush();

            if (!out)
            {
                cleanup();
                return false;
            }
        }

        {
            std::ofstream out(
                magnet_path,
                std::ios::trunc
            );

            if (!out)
            {
                cleanup();
                return false;
            }

            out << magnet;

            out.flush();

            if (!out)
            {
                cleanup();
                return false;
            }
        }

        {
            std::ofstream out(
                manifest_path,
                std::ios::trunc
            );

            if (!out)
            {
                cleanup();
                return false;
            }

            lt::file_storage const& files =
                ti->files();

            for (
                lt::file_index_t const index
                : files.file_range()
            )
            {
                if (
                    files.pad_file_at(index)
                )
                {
                    continue;
                }

                std::string const path =
                    files.file_path(index);

                std::int64_t const size =
                    files.file_size(index);

                out
                    << "FILE\t"
                    << size
                    << "\t"
                    << hex_encode(path)
                    << "\n";
            }

            out.flush();

            if (!out)
            {
                cleanup();
                return false;
            }
        }

        ::chmod(
            info_path.c_str(),
            0600
        );

        ::chmod(
            manifest_path.c_str(),
            0600
        );

        ::chmod(
            magnet_path.c_str(),
            0600
        );

        pid_t const child =
            ::fork();

        if (child < 0)
        {
            cleanup();
            return false;
        }

        if (child == 0)
        {
            std::string const bridge =
                base
                + "/torrent-approval-bridge";

            ::execl(
                bridge.c_str(),
                "torrent-approval-bridge",
                info_path.c_str(),
                manifest_path.c_str(),
                magnet_path.c_str(),
                static_cast<char*>(
                    nullptr
                )
            );

            _exit(127);
        }

        int status=0;

        for (;;)
        {
            pid_t const result =
                ::waitpid(
                    child,
                    &status,
                    0
                );

            if (result >= 0)
                break;

            if (errno == EINTR)
                continue;

            cleanup();
            return false;
        }

        cleanup();

        return (
            WIFEXITED(status)
            && WEXITSTATUS(status) == 0
        );
    }
    catch (
        std::exception const& exc
    )
    {
        cleanup();

        std::cerr
            << "approval connector: "
            << exc.what()
            << "\n";

        return false;
    }
}

}
