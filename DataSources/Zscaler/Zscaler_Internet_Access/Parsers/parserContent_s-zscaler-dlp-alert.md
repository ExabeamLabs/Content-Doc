#### Parser Content
```Java
{
Name = s-zscaler-dlp-alert
  Vendor = Zscaler
  Product = Zscaler Internet Access
  Lms = Splunk
  DataType = "dlp-alert"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """dlpengine=""", """vendor=Zscaler""", """event_id=""", """url=""" ]
  Fields = [
    """({time}\d\d\d\d-\d\d-\d\d \d{1,100}:\d{1,100}:\d{1,100})""",
    """\saction=({outcome}.+?)\s{0,100}(\w+=|$)""",
    """\sprotocol=({protocol}.+?)\s{0,100}(\w+=|$)""",
    """\sserverip=(?:0.0.0.0|({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))""",
    """\suseragent=({user_agent}.+?)\s{0,100}(\w+=|$)""",
    """\sClientIP=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\suser=({domain}[\w.\-]{1,2000})->({user}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
    """\suser=(?![^\s]{1,2000}@[^\s]{1,2000})({user}[^\s]{1,2000})\s{0,100}(\w+=|$)""",
    """\suser=(?=[^\s]{1,2000}@[^\s]{1,2000})({user_email}({user}[^\s@]{1,2000})@[^\s]{1,2000})\s{0,100}(\w+=|$)""",
    """\shostname=({host}[\w\-.]{1,2000})\s{0,100}(\w+=|$)""",
    """\sdlpengine=({alert_name}.+?)\s{0,100}(\w+=|$)""",
    """\sprotocol=({alert_type}.+?)\s{0,100}(\w+=|$)""",
    """\surl=({target}.+?)\s{0,100}(\w+=|$)""",
  ]
  DupFields = [ user_agent->browser ]
}
```