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
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}[^\s]{1,2000})""",
    """\s({host}[\w\-\.]{1,2000})\s{0,100}(PulseSecure|Juniper):""",
    """(Juniper:|PulseSecure:)\s{1,100}\S+\s{1,100}\S+\s{1,100}-\s{1,100}({host}[\w\.\-]{1,2000})\s{1,100}-""",
    """\stime="{1,20}({time}\d{1,100}-\d{1,100}-\d{1,100} \d{1,100}:\d{1,100}:\d{1,100})""",
    """(Juniper:|PulseSecure:)\s{1,100}({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """PulseSecure:.+?({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)\s{1,100}\-\s{1,100}({host}[\w\-.]{1,2000})""",
    """\s{1,100}-\s{1,100}\[({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]""",
    """\Wuser=([^\\]{1,2000}\\)?({user}[^\s\|]{1,2000})""",
    """\s{1,100}-\s{1,100}\[[^\]]{1,2000}\]\s{1,100}(({domain}[^\(]{1,2000})\\)?({user}.+?)\(({realm}[^\)]{1,2000})?\)""",
    """\sConnected to\s{1,100}(({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({dest_host}[\w\.-]{1,2000}))\s{1,100}port""",
    """\Wfw=({firewall}[a-fA-F\d.:]{1,2000})""",
    """\Wvpn=({vpn}[^=\|]{1,2000}?)(\||\s{1,100}\w+=|\s{0,100}$)""",
    """\Wrealm="({realm}[^"]{1,2000})""",
    """\Wroles="({roles}[^"]{1,2000})""",
    """\Wproto=({protocol}[^=\|]{1,2000}?)(\||\s{1,100}\w+=|\s{0,100}$)""",
    """\Wsrc=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\Wdst=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\ssrcport=({src_port}\d{1,100})""",
    """\sdstip=({dest_ip}[a-fA-F\d.:]{1,2000})""",
    """\Wdstname=({dest_host}[^=\|]{1,2000}?)(\||\s{1,100}\w+=|\s{0,100}$)""",
    """\sport=({dest_port}\d{1,100})""",
    """\stype=({vpn_type}[^=]{1,2000}?)(\s{1,100}\w+=|\s{0,100}$)""",
    """\sop=({op}[^=]{1,2000}?)(\s{1,100}\w+=|\s{0,100}$)""",
    """\sarg="({arg}[^"]{1,2000})""",
    """\sresult=({result}[^=]{1,2000}?)(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wsent=({bytes_out}\d{1,100})""",
    """\Wrcvd=({bytes_in}\d{1,100})""",
    """\sagent="({agent}[^"]{1,2000})""",
    """\sduration=({session_duration}\d{1,100})""",
    """\Wmsg="({additional_info}[^"]{1,2000})""",
  ]
  DupFields = ["user->account"]
}
```