#### Parser Content
```Java
{
Name = azure-event-hub-network-security-group-event
  DataType = "network-connection"
  Conditions = [""""category":"NetworkSecurityGroupEvent"""" ]
  Fields = ${MSParserTemplates.cef-azure-event-hub.Fields}[
     """\WrequestClientApplication=(|({app}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """category":"({activity}.*?[^\\])"""",
    """type":"({outcome}.*?[^\\])"""",
    """rule":"({ruleName}.*?[^\\])"""",
    """sourceIP":"({src_ip}.*?[^\\])"""",
    """destinationIP":"({dest_ip}.*?[^\\])"""",
    """ruleName":"({rule}.*?[^\\])"""",
    """direction":"({direction}.*?[^\\])"""",
  ]

cef-azure-event-hub = {
  Vendor = Microsoft
  Product = Azure
  Lms = Direct 
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Fields = [
      """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)\.\d{1,100}Z [\w\-.]{1,2000} Skyformation""",
      """"time":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
      """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S{1,2000})""",
      """\Wdvc=({host}\S{1,2000})""",
      """\Wdvchost=({host}[\w\-.]{1,2000})""",
      """\Wact=({activity}[^=]{1,2000})\s{1,100}(\w{1,100}=|$)""",
      """([^\|]{0,2000}\|){5}({activity}[^\|]{1,2000})""",
      """\WflexString1=({activity}[^=]{1,2000})\s{1,100}(\w{1,100}=|$)""",
      """\WdestinationServiceName =({app}[^=]{1,2000})\s{1,100}(\w{1,100}=|$)""",
      """\Wfname=({object}[^=]{1,2000})\s{1,100}(\w{1,100}=|$)""",
      """\Wmsg=({additional_info}[^=]{1,2000})\s{1,100}(\w{1,100}=|$)""",
      """\Wduser=(anonymous|({user_email}[^@=]{1,2000}@[^@=]{1,2000}?)|({user}.+?))(\s{1,100}\w{1,100}=|\s{0,100}$)""",
      """\Wsuser=(anonymous|({user_email}[^@=]{1,2000}@[^@=]{1,2000}?)|({user}.+?))(\s{1,100}\w{1,100}=|\s{0,100}$)""",
      """\Wsuid=(anonymous|({user_email}[^@=]{1,2000}@[^@=]{1,2000}?)|({user}.+?))(\s{1,100}\w{1,100}=|\s{0,100}$)""",
      """\Woutcome=({outcome}[^=]{1,2000})\s{1,100}(\w{1,100}=|$)""",
      """\Wsrc=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
      """\Wshost=(|--|({src_host}[^=]{1,2000}))(\s{1,100}\w+=|\s{0,100}$)""",
      """"clientIP":"({src_ip}[A-Fa-f.\d]{1,2000})""",
      """"description":"({additional_info}[^"]{1,2000})""",
      """Namespace:\s{0,100}(|({event_hub_namespace}[^\]]{1,2000}?))\s{0,100}[\];]""",
      """EventHub name:\s{0,100}(|({event_hub_name}[^\]]{1,2000}?))\s{0,100}\]""",
      """\[Namespace:\s{0,100}({host}\S{1,2000}) ; EventHub name:"""
  
}
```