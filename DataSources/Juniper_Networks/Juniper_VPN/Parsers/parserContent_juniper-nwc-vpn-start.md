#### Parser Content
```Java
{
Name = juniper-nwc-vpn-start
  Vendor = Juniper Networks
  Product = Juniper VPN
  Lms = Splunk
  DataType = "vpn-start"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ " id=", "NWC23464", "Session started" ]
  Fields = [
    """({host}[\w\-\.]+)\s*(PulseSecure|Juniper):""",
    """\stime="+({time}\d+-\d+-\d+ \d+:\d+:\d+).+?user""",
    """user=([^\\]+\\)?({user}.+?)\s+realm""",
    """src=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s""",
    """with IP(v4 address)?\s+({src_translated_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\sfw=({firewall}[a-fA-F\d.:]+)""",
    """\svpn=({vpn}[^=]+?)(\s+\w+=|\s*$)""",
    """\srealm="({realm}[^"]+)""",
    """\sroles="({roles}[^"]+)""",
    """\sproto=({protocol}[^=]+?)(\s+\w+=|\s*$)""",
    """\ssrcport=({src_port}\d+)""",
    """\sdstip=({dest_ip}[a-fA-F\d.:]+)""",
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
    """hostname\s+({src_host}[^"]+)"""
  ]
  DupFields = ["user->account"]
}
```