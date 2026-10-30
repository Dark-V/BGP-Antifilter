#!/usr/bin/env python3
"""Render an importable RouterOS 7 DNS failover configuration."""
import argparse
import ipaddress
from pathlib import Path


TEMPLATE = '''# BGP-Antifilter DNS failover, RouterOS 7. MikroTik remains the LAN DNS.
# Only /ip dns servers, the named scripts and schedulers are managed here.
# Proxy: @PROXY@, direct AdGuard: @DIRECT@. Health: @HEALTH@.
/system scheduler remove [find where name="bgp-dns-watch"]
/system scheduler remove [find where name="bgp-dns-startup"]
/system script remove [find where name="bgp-dns-watch"]
/system script remove [find where name="bgp-dns-direct"]

/system script add name=bgp-dns-direct policy=read,write,test source={
    :global bgpDnsGood; :set bgpDnsGood 0
    :global bgpDnsBad; :set bgpDnsBad 0
    /ip dns set servers=@DIRECT@
    /ip dns cache flush
}

/system script add name=bgp-dns-watch policy=read,write,test,ftp source={
    :if ([/system script job print count-only where script="bgp-dns-watch"] > 1) do={ :return }
    :local proxyDns "@PROXY@"
    :local directDns "@DIRECT@"
    :local healthy false
    :global bgpDnsGood
    :global bgpDnsBad
    :if ([:typeof $bgpDnsGood] = "nothing") do={ :set bgpDnsGood 0 }
    :if ([:typeof $bgpDnsBad] = "nothing") do={ :set bgpDnsBad 0 }

    :do {
        :local probe [/tool fetch url="@HEALTH@" output=user as-value idle-timeout=2s duration=3s]
        :if (($probe->"status") = "finished") do={
            :if ([:find ($probe->"data") "\\"ready\\":true"] != nil) do={ :set healthy true }
        }
    } on-error={ :set healthy false }

    :if ($healthy) do={
        :set bgpDnsBad 0
        :if ($bgpDnsGood < @UP@) do={ :set bgpDnsGood ($bgpDnsGood + 1) }
        :if (($bgpDnsGood >= @UP@) && ([:tostr [/ip dns get servers]] != $proxyDns)) do={
            /ip dns set servers=$proxyDns
            /ip dns cache flush
            :log info "BGP DNS: proxy ready, using proxy"
        }
    } else={
        :set bgpDnsGood 0
        :if ($bgpDnsBad < @DOWN@) do={ :set bgpDnsBad ($bgpDnsBad + 1) }
        :if (($bgpDnsBad >= @DOWN@) && ([:tostr [/ip dns get servers]] != $directDns)) do={
            /ip dns set servers=$directDns
            /ip dns cache flush
            :log warning "BGP DNS: proxy unavailable, using direct AdGuard"
        }
    }
}

# Install and boot into direct mode. Enable proxy only after successful probes.
/system script run bgp-dns-direct
/system scheduler add name=bgp-dns-startup start-time=startup interval=0s policy=read,write,test on-event="/system script run bgp-dns-direct"
/system scheduler add name=bgp-dns-watch start-time=00:00:00 interval=5s policy=read,write,test,ftp on-event="/system script run bgp-dns-watch"
'''


def render(proxy, direct, health_port=8053, up=3, down=2):
    proxy = str(ipaddress.IPv4Address(proxy))
    direct = str(ipaddress.IPv4Address(direct))
    if proxy == direct or proxy == "0.0.0.0":
        raise ValueError("Proxy must have its own address")
    if not 1 <= health_port <= 65535 or not 1 <= up <= 100 or not 1 <= down <= 100:
        raise ValueError("Invalid port or probe thresholds")
    result = TEMPLATE
    for key, value in {"PROXY": proxy, "DIRECT": direct, "HEALTH": f"http://{proxy}:{health_port}/ready", "UP": up, "DOWN": down}.items():
        result = result.replace(f"@{key}@", str(value))
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--proxy", required=True, help="IPv4 address of the DNS proxy (BIRD_IP)")
    parser.add_argument("--direct", default="192.168.88.16")
    parser.add_argument("--health-port", type=int, default=8053)
    parser.add_argument("--up", type=int, default=3)
    parser.add_argument("--down", type=int, default=2)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    text = render(args.proxy, args.direct, args.health_port, args.up, args.down)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(text, encoding="utf-8")
    print(args.output)


if __name__ == "__main__":
    main()
