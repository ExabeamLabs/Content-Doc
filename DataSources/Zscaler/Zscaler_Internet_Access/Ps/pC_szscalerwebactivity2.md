#### Parser Content
```Java
{
Name = s-zscaler-web-activity-2
  Conditions = [ """threatclass=Clean Transaction""", """bwthrottle=""", """urlsupercategory=""" ]

s-zscaler-web-activity = {
  Vendor = Zscaler
  Product = Zscaler Internet Access
  Lms = Splunk
  DataType = "web-activity"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """({time}\d\d\d\d-\d\d-\d\d \d{1,100}:\d{1,100}:\d{1,100})\s{1,100}(\w+=|$)""",
    """\sreason=(Allowed|({failure_reason}.+?))\s{0,100}(\w+=|$)""",
    """\saction=({action}.+?)\s{0,100}(\w+=|$)""",
    """\sprotocol=({protocol}.+?)\s{0,100}(\w+=|$)""",
    """\srequestsize=({bytes_out}\d{1,100})""",
    """\sresponsesize=({bytes_in}\d{1,100})""",
    """\surlsupercategory=({categories}({category}[^;,=]{1,2000})[^=]{0,2000}?)\s{1,100}(\w+|$)""",
    """\surlcategory=({categories}({category}[^;,=]{1,2000})[^=]{0,2000}?)\s{1,100}(\w+|$)""",
    """\sserverip=(?:0.0.0.0|({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))""",
    """\srequestmethod=({method}.+?)\s{0,100}(\w+=|$)""",
    """\srefererURL=(?:None|({referrer}[^\s]{1,2000}))\s{0,100}(\w+=|$)""",
    """\suseragent=(Unknown|({user_agent}.+?))\s{0,100}(\w+=|$)""",
    """\sstatus=({result_code}\d{1,100})""",
    """\sClientIP=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\sclientpublicIP=({src_ip}[A-Fa-f:\d.]{1,2000})""",
    """\suser=({domain}[\w.\-]{1,2000})->({user}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
    """\suser=(?![^\s]{1,2000}@[^\s]{1,2000})({user}[^\s]{1,2000})\s{0,100}(\w+=|$)""",
    """\suser=(?=[^\s]{1,2000}@[^\s]{1,2000})({user_email}[^\s@]{1,2000}@[^\s@]{1,2000})\s{0,100}(\w+=|$)""",
    """\surl=(?:None|({full_url}[^\s]{1,2000}))\s{0,100}(\w+=|$)""",
    """\surl=(\w+:\/{2})?[^\/]{1,2000}({uri_path}\/[^?\s]{1,2000})""",
    """\surl=(\w+:\/+)?[^|\/:]{1,2000}(:\d{1,100})?[^|?]{1,2000}({uri_query}\?[^\s]{1,2000})""",
    """\shostname=(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|({web_domain}\S+))""",    
    """\spagerisk=({risk_level}\d{1,100})""",
    """\sfileclass=(?:None|({mime}.+?))\s{0,100}(\w+=|$)""",
    """\sappname=({app}.+?)\s{1,100}(\w+|$)""",
    """\suseragent=[^=]{0,2000}?({os}iOS|Android|BlackBerry|iPhone OS|Windows Phone|BeOS|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin)[^=]{0,2000}?\s{1,100}(\w+=|$)""",
    """\shostname=[^\s=]{0,2000}?({top_domain}(?!(?:\d{1,100}\.){3}\d{1,100})[^\.\s]{1,2000}(?=(?:\.(?:com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za)(?::\d{1,100})?)+(?:\s{1,100}\w+=|\/))[^\s:\/]{1,2000})""",
  ]
  DupFields = [ "user_agent->browser" 
}
```