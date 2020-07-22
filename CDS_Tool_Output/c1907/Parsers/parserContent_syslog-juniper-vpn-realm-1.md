#### Parser Content
```Java
{
Name = syslog-juniper-vpn-realm-1
  Vendor = Juniper Networks
  Lms = Syslog
  DataType = "vpn-start"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ "Host Checker policy ", " passed on host " ]
  Fields = [
    """passed on host '({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+PulseSecure:\s+({time}\d\d\d\d\-\d\d-\d\d \d\d:\d\d:\d\d)\s+(\S+\s+){3}\[\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\]\s+({user}[^\s\(\)]+)\((?:unknown|({realm}[^)]+))\)""",
    """for user '({user}[^']+)'""",
    """\stime="({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """\suser=({user}[^\s].*?)(\s+\w+=|\s*$)""",
    """\srealm="({realm}[^"]+)""",
    """\ssrc=({src_ip}[a-fA-F\d.:]+)""",
    """\sdstip=({dest_ip}[a-fA-F\d.:]+)""",
    """({host}(?!\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})[\w.\-]+) PulseSecure:""",
    """\sfw=({firewall}[a-fA-F\d.:]+)""",
    """\svpn=({vpn}[^=]+?)(\s+\w+=|\s*$)""",
    """\sroles="({roles}[^"]+)""",
    """\sproto=({protocol}[^=]+?)(\s+\w+=|\s*$)""",
    """\ssrcport=({src_port}\d+)""",
    """\sdstname=({dest_host}[^=]+?)(\s+\w+=|\s*$)""",
    """\sport=({dest_port}\d+)""",
    """\stype=({vpn_type}[^=]+?)(\s+\w+=|\s*$)""",
    """\sop=({op}[^=]+?)(\s+\w+=|\s*$)""",
    """\sarg="({arg}[^"]+)""",
    """\sresult=({result}[^=]+?)(\s+\w+=|\s*$)""",
    """\ssent=({bytes_out}\d+)""",
    """\srcvd=({bytes_in}\d+)""",
    """\sagent="({agent}[^"]+)""",
    """\sduration=({session_duration}\d+)""",
    """\smsg="({additional_info}[^"]+)""",
  ]
  DupFields = [ "dest_ip->host" ]
}
```