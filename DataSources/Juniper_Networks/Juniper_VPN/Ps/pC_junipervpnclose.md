#### Parser Content
```Java
{
Name = juniper-vpn-close
  Vendor = Juniper Networks
  Product = Juniper VPN
  Lms = Splunk
  DataType = "vpn-end"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """ Closed connection to """, """ bytes read """, """ bytes written """ ]
  Fields = [
    """(Juniper|PulseSecure):\s{0,100}({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """"@timestamp":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}Z)""",
    """\w{3}\s{1,100}\d{1,2}\s{1,100}\d{2}:\d{2}:\d{2}\s{1,100}({host}[\w\.-]{1,2000})\s{1,100}\S*?[\[:\s]""",
    """exabeam_host=([^=]{1,2000}?@\s{0,100})?({host}[^\s]{1,2000})""",
    """({host}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|[\w\-\.]{1,2000})\s{0,100}(Juniper|PulseSecure):""",
    """:\s{0,100}({time}\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s""",
    """- \[({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]\s{1,100}(?:({domain}\w+)\\)?({user}[^\(\[]{1,2000}?)[\(\[]""",
    """Closed connection to (?:({src_translated_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({dest_host}[\w.\-]{1,2000}))""",
    """- Closed connection to \S+\s{1,100}port ({dest_port}\d{1,100})""",
    """\stime="({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """\suser=({user}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
    """\ssrc=({src_ip}[a-fA-F\d.:]{1,2000})""",
    """\safter\s{1,100}({session_duration}\d{1,100})\s{1,100}seconds""",
    """\swith\s{1,100}({bytes_in}\d{1,100})\s{1,100}bytes read""",
    """\sand\s{1,100}({bytes_out}\d{1,100})\s{1,100}bytes written"""
    """\sfw=({firewall}[a-fA-F\d.:]{1,2000})""",
    """\svpn=[\\"]{0,2000}({vpn}.+?)[\\"]{0,2000}(\s{1,100}\w+=|\s{0,100}$)""",
    """\srealm=[\\"]{0,2000}({realm}.+?)[\\"]{0,2000}(\s{1,100}\w+=|\s{0,100}$)""",
    """\sroles=[\\"]{0,2000}({roles}.+?)[\\"]{0,2000}(\s{1,100}\w+=|\s{0,100}$)""",
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
  ]
}
```