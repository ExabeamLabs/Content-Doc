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
    """\Wcat=({categories}({category}[^;,=]+)[^=]*?)\s{1,100}(\w+=|$)""",
    """\Wduser=({user}[^\s@]+)\s{1,100}(\w+=|$)""",
    """\Wduser=({user_email}[^\s@]+@[^\s@]+)\s{1,100}(\w+=|$)""",
    """\Wsrc=({src_ip}.+?)\s{1,100}(\w+=|$)""",
    """\Wdst=({dest_ip}.+?)\s{1,100}(\w+=|$)""",
    """\Wshost=({src_host}.+?)\s{1,100}(\w+=|$)""",
    """\Wdhost=({dest_host}.+?)\s{1,100}(\w+=|$)""",
    """\Wapp=({protocol}.+?)\s{1,100}(\w+=|$)""",
    """\Wmsg=({additional_info}.+?)\s{1,100}(\w+=|$)""",
    """\Win=({bytes_in}.+?)\s{1,100}(\w+=|$)""",
    """\Wout=({bytes_out}.+?)\s{1,100}(\w+=|$)""",
    """\Wrequest=(-|({full_url}(({protocol}[^:\\\/\s,"]+):[\\\/]+)?(({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({web_domain}[^\\\/\s:,"]+))?(:({dest_port}\d{1,100}))?({uri_path}\/[^\?",]*?)?({uri_query}\?[^"]*?)?))\s{1,100}(\w+=|$)""",
    """\Wspt=({src_port}.+?)\s{1,100}(\w+=|$)""",
    """\Wdpt=({dest_port}.+?)\s{1,100}(\w+=|$)""",
    """\Wdhost=({web_domain}.+?)\s{1,100}(\w+=|$)""",
    """\Wdhost=[^\s]*?(?!\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})([^"\s]*\.)?({top_domain}[^\s\/."]+(?:\.(?:com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za|by|mx|pro|online))+)""",
  ]
}
```