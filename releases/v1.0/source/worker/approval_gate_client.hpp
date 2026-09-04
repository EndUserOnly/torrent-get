#pragma once

#include <libtorrent/torrent_info.hpp>

#include <memory>
#include <string>


namespace torrent_get::approval
{

bool admit(
    std::shared_ptr<
        libtorrent::torrent_info const
    > const& ti,
    std::string const& magnet,
    std::string const& job_id
);

}
