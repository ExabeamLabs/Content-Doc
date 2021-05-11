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
    """\w{3}\s{1,100}\d{1,2}\s{1,100}\d{2}:\d{2}:\d{2}\s{1,100}({host}[\w\.-]+)\s{1,100}\S*?[\[:\s]""",
    """exabeam_host=([^=]+?@\s{0,100})?({host}[^\s]+)""",
    """({host}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|[\w\-\.]+)\s{0,100}(Juniper|PulseSecure):""",
    """:\s{0,100}({time}\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s""",
    """- \[({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]\s{1,100}(?:({domain}\w+)\\)?({user}[^\(\[]+?)[\(\[]""",
    """Closed connection to (?:({src_translated_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({dest_host}[\w.\-]+))""",
    """- Closed connection to \S+\s{1,100}port ({dest_port}\d{1,100})""",
    """\stime="({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """\suser=({user}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
    """\ssrc=({src_ip}[a-fA-F\d.:]+)""",
    """\safter\s{1,100}({session_duration}\d{1,100})\s{1,100}seconds""",
    """\swith\s{1,100}({bytes_in}\d{1,100})\s{1,100}bytes read""",
    """\sand\s{1,100}({bytes_out}\d{1,100})\s{1,100}bytes written"""
    """\sfw=({firewall}[a-fA-F\d.:]+)""",
    """\svpn=[\\"]*({vpn}.+?)[\\"]*(\s{1,100}\w+=|\s{0,100}$)""",
    """\srealm=[\\"]*({realm}.+?)[\\"]*(\s{1,100}\w+=|\s{0,100}$)""",
    """\sroles=[\\"]*({roles}.+?)[\\"]*(\s{1,100}\w+=|\s{0,100}$)""",
    """\sproto=({protocol}[^=]+?)(\s{1,100}\w+=|\s{0,100}$)""",
    """\ssrcport=({src_port}\d{1,100})""",
    """\sdstip=({dest_ip}[a-fA-F\d.:]+)""",
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
}
```