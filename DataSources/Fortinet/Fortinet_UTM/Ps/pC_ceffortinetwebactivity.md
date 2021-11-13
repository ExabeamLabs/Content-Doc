#### Parser Content
```Java
{
Name = cef-fortinet-web-activity
  Vendor = Fortinet
  Product = Fortinet UTM
  Lms = Direct
  DataType = "web-activity"
  IsHVF = true
  TimeFormat = "epoch"
  Conditions = [ """CEF:""", """|Fortinet|FortiGate-VM|""", """|webfilter""" ]
  Fields = [
    """\Wrt=({time}.+?)\s{1,100}(\w+=|$)""",
    """\Wdvc=({host}.+?)\s{1,100}(\w+=|$)""",
    """\Wdvchost=({host}.+?)\s{1,100}(\w+=|$)""",
    """\Wact=({action}.+?)\s{1,100}(\w+=|$)""",
    """\Wcat=({categories}({category}[^;,=]{1,2000})[^=]{0,2000}?)\s{1,100}(\w+=|$)""",
    """\Wduser=({user}[^\s@]{1,2000})\s{1,100}(\w+=|$)""",
    """\Wduser=({user_email}[^\s@]{1,2000}@[^\s@]{1,2000})\s{1,100}(\w+=|$)""",
    """\Wsrc=({src_ip}.+?)\s{1,100}(\w+=|$)""",
    """\Wdst=({dest_ip}.+?)\s{1,100}(\w+=|$)""",
    """\Wshost=({src_host}.+?)\s{1,100}(\w+=|$)""",
    """\Wdhost=({dest_host}.+?)\s{1,100}(\w+=|$)""",
    """\Wapp=({protocol}.+?)\s{1,100}(\w+=|$)""",
    """\Wmsg=({additional_info}.+?)\s{1,100}(\w+=|$)""",
    """\Win=({bytes_in}.+?)\s{1,100}(\w+=|$)""",
    """\Wout=({bytes_out}.+?)\s{1,100}(\w+=|$)""",
    """\Wrequest=(-|({full_url}(({protocol}[^:\\\/\s,"]{1,2000}):[\\\/]{1,2000})?(({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({web_domain}[^\\\/\s:,"]{1,2000}))?(:({dest_port}\d{1,100}))?({uri_path}\/[^\?",]{0,2000}?)?({uri_query}\?[^"]{0,2000}?)?))\s{1,100}(\w+=|$)""",
    """\Wspt=({src_port}.+?)\s{1,100}(\w+=|$)""",
    """\Wdpt=({dest_port}.+?)\s{1,100}(\w+=|$)""",
    """\Wdhost=({web_domain}.+?)\s{1,100}(\w+=|$)""",
  ]


}
```