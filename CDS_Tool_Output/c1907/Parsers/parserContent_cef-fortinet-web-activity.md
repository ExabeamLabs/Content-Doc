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
    """\Wrt=({time}.+?)\s+(\w+=|$)""",
    """\Wdvc=({host}.+?)\s+(\w+=|$)""",
    """\Wdvchost=({host}.+?)\s+(\w+=|$)""",
    """\Wact=({action}.+?)\s+(\w+=|$)""",
    """\Wcat=({categories}({category}[^;,=]+)[^=]*?)\s+(\w+=|$)""",
    """\Wduser=({user}[^\s@]+)\s+(\w+=|$)""",
    """\Wduser=({user_email}[^\s@]+@[^\s@]+)\s+(\w+=|$)""",
    """\Wsrc=({src_ip}.+?)\s+(\w+=|$)""",
    """\Wdst=({dest_ip}.+?)\s+(\w+=|$)""",
    """\Wshost=({src_host}.+?)\s+(\w+=|$)""",
    """\Wdhost=({dest_host}.+?)\s+(\w+=|$)""",
    """\Wapp=({protocol}.+?)\s+(\w+=|$)""",
    """\Wmsg=({additional_info}.+?)\s+(\w+=|$)""",
    """\Win=({bytes_in}.+?)\s+(\w+=|$)""",
    """\Wout=({bytes_out}.+?)\s+(\w+=|$)""",
    """\Wrequest=(-|({full_url}(({protocol}[^:\\\/\s,"]+):[\\\/]+)?(({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({web_domain}[^\\\/\s:,"]+))?(:({dest_port}\d+))?({uri_path}\/[^\?",]*?)?({uri_query}\?[^"]*?)?))\s+(\w+=|$)""",
    """\Wspt=({src_port}.+?)\s+(\w+=|$)""",
    """\Wdpt=({dest_port}.+?)\s+(\w+=|$)""",
    """\Wdhost=({web_domain}.+?)\s+(\w+=|$)""",
    """\Wdhost=[^\s]*?(?!\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})([^"\s]*\.)?({top_domain}[^\s\/."]+(?:\.(?:com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za|by|mx|pro|online))+)""",
  ]
}
```