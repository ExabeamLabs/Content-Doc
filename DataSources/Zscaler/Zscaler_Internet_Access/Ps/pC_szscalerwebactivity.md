#### Parser Content
```Java
{
Name = s-zscaler-web-activity
  Conditions = [ """dlpengine=None""", """vendor=Zscaler""", """event_id=""", """url=""" ]

s-zscaler-web-activity = {
  Vendor = Zscaler
  Product = Zscaler Internet Access
  Lms = Splunk
  DataType = "web-activity"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S{1,2000})""",
    """({time}\d\d\d\d-\d\d-\d\d \d{1,100}:\d{1,100}:\d{1,100})\s{1,100}(\w+=|$)""",
    """\sreason=(Allowed|({failure_reason}[^=]{1,2000}?))\s{0,100}(\w+=|$)""",
    """\saction=({action}[^=]{1,2000}?)\s{0,100}(\w+=|$)""",
    """\sprotocol=({protocol}[^=]{1,2000}?)\s{0,100}(\w+=|$)""",
    """\srequestsize=({bytes_out}\d{1,100})""",
    """\sresponsesize=({bytes_in}\d{1,100})""",
    """\surlsupercategory=({categories}({category}[^;,=]{1,2000})[^=]{0,2000}?)\s{1,100}(\w+|$)""",
    """\surlcategory=({categories}({category}[^;,=]{1,2000})[^=]{0,2000}?)\s{1,100}(\w+|$)""",
    """\sserverip=(?:0.0.0.0|({dest_ip}[A-Fa-f\d:.]{1,2000}))""",
    """\srequestmethod=(NA|({method}[^=]{1,2000}?))\s{0,100}(\w+=|$)""",
    """\srefererURL=(?:None|({referrer}[^\s]{1,2000}))\s{0,100}(\w+=|$)""",
    """\suseragent=(Unknown|({user_agent}[^=]{1,2000}?))\s{0,100}(\w+=|$)""",
    """\sstatus=({result_code}\d{1,100})""",
    """\sclientpublicIP=({src_ip}[A-Fa-f:\d.]{1,2000})""",
    """\sClientIP=({src_ip}[A-Fa-f\d:.]{1,2000})""",
    """\suser=({domain}[\w.\-]{1,2000})->({user}[^=]{1,2000}?)(\s{1,100}\w+=|\s{0,100}$)""",
    """\suser=(?![^\s]{1,2000}@[^\s]{1,2000})({user}[^\s]{1,2000})\s{0,100}(\w+=|$)""",
    """\suser=(?=[^\s]{1,2000}@[^\s]{1,2000})({user_email}[^\s@]{1,2000}@[^\s@]{1,2000})\s{0,100}(\w+=|$)""",
    """\surl=(?:None|({full_url}[^\s]{1,2000}))\s{0,100}(\w+=|$)""",
    """\surl=(\w{1,2000}:\/{2})?[^\/]{1,2000}({uri_path}\/[^?\s]{1,2000})""",
    """\surl=(\w{1,2000}:\/+)?[^|\/:]{1,2000}(:\d{1,100})?[^|?]{1,2000}({uri_query}\?[^\s]{1,2000})""",
    """\shostname=(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|({web_domain}\S{1,2000}))""",    
    """\spagerisk=({risk_level}\d{1,100})""",
    """\sfileclass=(?:None|({mime}[^=]{1,2000}?))\s{0,100}(\w+=|$)""",
    """\sappname=({app}[^=]{1,2000}?)\s{1,100}(\w+|$)""",
    """\slocation=({location}[^=]{1,2000}?)\s{1,100}\w+="""
  
}
```