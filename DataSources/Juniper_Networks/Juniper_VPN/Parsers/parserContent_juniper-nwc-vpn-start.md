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
    """({host}[\w\-\.]{1,2000})\s{0,100}(PulseSecure|Juniper):""",
    """\stime="{1,20}({time}\d{1,100}-\d{1,100}-\d{1,100} \d{1,100}:\d{1,100}:\d{1,100}).+?user""",
    """user=([^\\]{1,2000}\\)?({user}.+?)\s{1,100}realm""",
    """src=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s""",
    """with IP(v4 address)?\s{1,100}({src_translated_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\sfw=({firewall}[a-fA-F\d.:]{1,2000})""",
    """\svpn=({vpn}[^=]{1,2000}?)(\s{1,100}\w+=|\s{0,100}$)""",
    """\srealm="({realm}[^"]{1,2000})""",
    """\sroles="({roles}[^"]{1,2000})""",
    """\sproto=({protocol}[^=]{1,2000}?)(\s{1,100}\w+=|\s{0,100}$)""",
    """\ssrcport=({src_port}\d{1,100})""",
    """\sdstip=({dest_ip}[a-fA-F\d.:]{1,2000})""",
    """\sdstname=({dest_host}[^=]{1,2000}?)(\s{1,100}\w+=|\s{0,100}$)""",
    """\sport=({dest_port}\d{1,100})""",
    """\stype=({vpn_type}[^=]{1,2000}?)(\s{1,100}\w+=|\s{0,100}$)""",
    """\sop=({op}[^=]{1,2000}?)(\s{1,100}\w+=|\s{0,100}$)""",
    """\sarg="({arg}[^"]{1,2000})""",
    """\sresult=({result}[^=]{1,2000}?)(\s{1,100}\w+=|\s{0,100}$)""",
    """\ssent=({bytes_out}\d{1,100})""",
    """\srcvd=({bytes_in}\d{1,100})""",
    """\sagent="({agent}[^"]{1,2000})""",
    """\sduration=({session_duration}\d{1,100})""",
    """\smsg="({additional_info}[^"]{1,2000})""",
    """hostname\s{1,100}({src_host}[^"]{1,2000})"""
  ]
  DupFields = ["user->account"]
}
```