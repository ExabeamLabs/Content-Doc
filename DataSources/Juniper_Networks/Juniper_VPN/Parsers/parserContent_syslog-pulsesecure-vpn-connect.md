#### Parser Content
```Java
{
Name = syslog-pulsesecure-vpn-connect
  Vendor = Juniper Networks
  Product = Juniper VPN
  Lms = Direct
  DataType = "vpn-start"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """PulseSecure: """, """ Connected to """ ]
  Fields = [
    """exabeam_host=([^=]+@\s{0,100})?({host}[^\s]+)""",
    """\s({host}[\w\-\.]+)\s{0,100}(PulseSecure|Juniper):""",
    """(Juniper:|PulseSecure:)\s{1,100}\S+\s{1,100}\S+\s{1,100}-\s{1,100}({host}[\w\.\-]+)\s{1,100}-""",
    """\stime="{1,20}({time}\d{1,100}-\d{1,100}-\d{1,100} \d{1,100}:\d{1,100}:\d{1,100})""",
    """(Juniper:|PulseSecure:)\s{1,100}({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """PulseSecure:.+?({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)\s{1,100}\-\s{1,100}({host}[\w\-.]+)""",
    """\s{1,100}-\s{1,100}\[({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]""",
    """\Wuser=([^\\]+\\)?({user}[^\s\|]+)""",
    """\s{1,100}-\s{1,100}\[[^\]]+\]\s{1,100}(({domain}[^\(]+)\\)?({user}.+?)\(({realm}[^\)]+)?\)""",
    """\sConnected to\s{1,100}(({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({dest_host}[\w\.-]+))\s{1,100}port""",
    """\Wfw=({firewall}[a-fA-F\d.:]+)""",
    """\Wvpn=({vpn}[^=\|]+?)(\||\s{1,100}\w+=|\s{0,100}$)""",
    """\Wrealm="({realm}[^"]+)""",
    """\Wroles="({roles}[^"]+)""",
    """\Wproto=({protocol}[^=\|]+?)(\||\s{1,100}\w+=|\s{0,100}$)""",
    """\Wsrc=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\Wdst=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\ssrcport=({src_port}\d{1,100})""",
    """\sdstip=({dest_ip}[a-fA-F\d.:]+)""",
    """\Wdstname=({dest_host}[^=\|]+?)(\||\s{1,100}\w+=|\s{0,100}$)""",
    """\sport=({dest_port}\d{1,100})""",
    """\stype=({vpn_type}[^=]+?)(\s{1,100}\w+=|\s{0,100}$)""",
    """\sop=({op}[^=]+?)(\s{1,100}\w+=|\s{0,100}$)""",
    """\sarg="({arg}[^"]+)""",
    """\sresult=({result}[^=]+?)(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wsent=({bytes_out}\d{1,100})""",
    """\Wrcvd=({bytes_in}\d{1,100})""",
    """\sagent="({agent}[^"]+)""",
    """\sduration=({session_duration}\d{1,100})""",
    """\Wmsg="({additional_info}[^"]+)""",
  ]
  DupFields = ["user->account"]
}
```