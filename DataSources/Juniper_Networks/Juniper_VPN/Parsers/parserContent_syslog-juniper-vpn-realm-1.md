#### Parser Content
```Java
{
Name = syslog-juniper-vpn-realm-1
  Vendor = Juniper Networks
  Product = Juniper VPN
  Lms = Syslog
  DataType = "vpn-start"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ "Host Checker policy ", " passed on host " ]
  Fields = [
    """passed on host '({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s{1,100}PulseSecure:((\s\S+){3}\s|\s{1,100})({time}\d\d\d\d\-\d\d-\d\d \d\d:\d\d:\d\d)\s{1,100}(\S+\s{1,100}){3}\[\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\]\s{1,100}({user}[^\s\(\)]+)\((|unknown|({realm}[^)]+))\)""",
    """for user '({user}[^']+)'""",
    """\stime="({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """\suser=({user}[^\s].*?)(\s{1,100}\w+=|\s{0,100}$)""",
    """\srealm="({realm}[^"]+)""",
    """\ssrc=({src_ip}[a-fA-F\d.:]+)""",
    """\sdstip=({dest_ip}[a-fA-F\d.:]+)""",
    """({host}[\w.\-]+) PulseSecure:""",
    """\sfw=({firewall}[a-fA-F\d.:]+)""",
    """\svpn=({vpn}[^=]+?)(\s{1,100}\w+=|\s{0,100}$)""",
    """\sroles="({roles}[^"]+)""",
    """\sproto=({protocol}[^=]+?)(\s{1,100}\w+=|\s{0,100}$)""",
    """\ssrcport=({src_port}\d{1,100})""",
    """\sdstname=({dest_host}[^=]+?)(\s{1,100}\w+=|\s{0,100}$)""",
    """\sport=({dest_port}\d{1,100})""",
    """\stype=({vpn_type}[^=]+?)(\s{1,100}\w+=|\s{0,100}$)""",
    """\sop=({op}[^=]+?)(\s{1,100}\w+=|\s{0,100}$)""",
    """\sarg="({arg}[^"]+)""",
    """\sresult=({result}[^=]+?)(\s{1,100}\w+=|\s{0,100}$)""",
    """\ssent=({bytes_out}\d{1,100})""",
    """\srcvd=({bytes_in}\d{1,100})""",
    """\sagent="({agent}[^"]+)""",
    """\sduration=({session_duration}\d{1,100})""",
    """\smsg="({additional_info}[^"]+)""",
  ]
  DupFields = [ "dest_ip->host" , "user->account"]
}
```