#### Parser Content
```Java
{
Name = syslog-pulsesecure-vpn-connect
  Vendor = Juniper Networks
  Lms = Direct
  DataType = "vpn-start"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """PulseSecure: """, """ Connected to """ ]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}[^\s]+)""",
    """\s({host}[\w\-\.]+)\s*(PulseSecure|Juniper):""",
    """(Juniper:|PulseSecure:)\s+\S+\s+\S+\s+-\s+({host}[\w\.\-]+)\s+-""",
    """\stime="+({time}\d+-\d+-\d+ \d+:\d+:\d+)""",
    """(Juniper:|PulseSecure:)\s+({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """\s+-\s+\[({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]""",
    """\Wuser=([^\\]+\\)?({user}[^\s\|]+)""",
    """\s+-\s+\[[^\]]+\]\s+(({domain}[^\(]+)\\)?({user}.+?)\(({realm}[^\)]+)?\)""",
    """\sConnected to\s+(({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({dest_host}[\w\.-]+))\s+port""",
    """\Wfw=({firewall}[a-fA-F\d.:]+)""",
    """\Wvpn=({vpn}[^=\|]+?)(\||\s+\w+=|\s*$)""",
    """\Wrealm="({realm}[^"]+)""",
    """\Wroles="({roles}[^"]+)""",
    """\Wproto=({protocol}[^=\|]+?)(\||\s+\w+=|\s*$)""",
    """\Wsrc=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\Wdst=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\ssrcport=({src_port}\d+)""",
    """\sdstip=({dest_ip}[a-fA-F\d.:]+)""",
    """\Wdstname=({dest_host}[^=\|]+?)(\||\s+\w+=|\s*$)""",
    """\sport=({dest_port}\d+)""",
    """\stype=({vpn_type}[^=]+?)(\s+\w+=|\s*$)""",
    """\sop=({op}[^=]+?)(\s+\w+=|\s*$)""",
    """\sarg="({arg}[^"]+)""",
    """\sresult=({result}[^=]+?)(\s+\w+=|\s*$)""",
    """\Wsent=({bytes_out}\d+)""",
    """\Wrcvd=({bytes_in}\d+)""",
    """\sagent="({agent}[^"]+)""",
    """\sduration=({session_duration}\d+)""",
    """\Wmsg="({additional_info}[^"]+)""",
  ]
  DupFields = ["user->account"]
}
```