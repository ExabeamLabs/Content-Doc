#### Parser Content
```Java
{
 = {
s-zscaler-web-activity = {
  Vendor = Zscaler
  Product = Zscaler
  Lms = Splunk
  DataType = "web-activity"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """({time}\d\d\d\d-\d\d-\d\d \d+:\d+:\d+)\s+(\w+=|$)""",
    """\sreason=(Allowed|({failure_reason}.+?))\s*(\w+=|$)""",
    """\saction=({action}.+?)\s*(\w+=|$)""",
    """\sprotocol=({protocol}.+?)\s*(\w+=|$)""",
    """\srequestsize=({bytes_out}\d+)""",
    """\sresponsesize=({bytes_in}\d+)""",
    """\surlsupercategory=({categories}({category}[^;,=]+)[^=]*?)\s+(\w+|$)""",
    """\surlcategory=({categories}({category}[^;,=]+)[^=]*?)\s+(\w+|$)""",
    """\sserverip=(?:0.0.0.0|({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))""",
    """\srequestmethod=({method}.+?)\s*(\w+=|$)""",
    """\srefererURL=(?:None|({referrer}[^\s]+))\s*(\w+=|$)""",
    """\suseragent=(Unknown|({user_agent}.+?))\s*(\w+=|$)""",
    """\sstatus=({result_code}\d+)""",
    """\sClientIP=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\sclientpublicIP=({src_ip}[A-Fa-f:\d.]+)""",
    """\suser=({domain}[\w.\-]+)->({user}.+?)(\s+\w+=|\s*$)""",
    """\suser=(?![^\s]+@[^\s]+)({user}[^\s]+)\s*(\w+=|$)""",
    """\suser=(?=[^\s]+@[^\s]+)({user_email}[^\s@]+@[^\s@]+)\s*(\w+=|$)""",
    """\surl=(?:None|({full_url}[^\s]+))\s*(\w+=|$)""",
    """\surl=(\w+:\/{2})?[^\/]+({uri_path}\/[^?\s]+)""",
    """\surl=(\w+:\/+)?[^|\/:]+(:\d+)?[^|?]+({uri_query}\?[^\s]+)""",
    """\shostname=(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|({web_domain}\S+))""",    
    """\spagerisk=({risk_level}\d+)""",
    """\sfileclass=(?:None|({mime}.+?))\s*(\w+=|$)""",
    """\sappname=({app}.+?)\s+(\w+|$)""",
    """\suseragent=[^=]*?({os}iOS|Android|BlackBerry|iPhone OS|Windows Phone|BeOS|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin)[^=]*?\s+(\w+=|$)""",
    """\shostname=[^\s=]*?({top_domain}(?!(?:\d+\.){3}\d+)[^\.\s]+(?=(?:\.(?:com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za)(?::\d+)?)+(?:\s+\w+=|\/))[^\s:\/]+)""",
  ]
  DupFields = [ "user_agent->browser" ]
}
```