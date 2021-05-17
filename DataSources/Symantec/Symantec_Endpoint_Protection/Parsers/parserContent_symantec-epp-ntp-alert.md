#### Parser Content
```Java
{
Name = symantec-epp-ntp-alert
  Vendor = Symantec
  Product = Symantec Endpoint Protection
  Lms = Splunk
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """CIDS Signature string""", """Intrusion ID:""" ]
  Fields = [
    """Local:\s{0,100}({dest_ip}[a-fA-F:\.\d]{1,2000}),(Local:\s{0,100}(?:0+|({dest_host}[^,]{1,2000})))?.*?,Inbound,""",
    """Remote:\s{0,100}({src_ip}[a-fA-F:\.\d]{1,2000}),(Remote:\s{0,100}(?:0+|({src_host}[^,]{1,2000})))?.*?,Inbound,""",
    """Local:\s{0,100}({src_ip}[a-fA-F:\.\d]{1,2000}),(Local:\s{0,100}(?:0+|({src_host}[^,]{1,2000})))?.*?,Outbound,""",
    """Remote:\s{0,100}({dest_ip}[a-fA-F:\.\d]{1,2000}),(Remote:\s{0,100}(?:0+|({dest_host}[^,]{1,2000})))?.*?,Outbound,""",
    """Remote Host Name:\s{0,100}(|({src_host}[\w\-.]{1,2000})),(Remote Host IP:\s{0,100}(?:0+|({src_ip}[A-Fa-f:\d.]{1,2000})),)?.*?,Inbound,""",
    """Remote Host Name:\s{0,100}(|({dest_host}[\w\-.]{1,2000})),(Remote Host IP:\s{0,100}(?:0+|({dest_ip}[A-Fa-f:\d.]{1,2000})),)?.*?,Outbound,""",
    """Local Host IP:\s{0,100}({src_ip}[a-fA-F\d.:]{1,2000}).*?,Outbound,""",
    """Local Host IP:\s{0,100}({dest_ip}[a-fA-F\d.:]{1,2000}).*?,Inbound,""",
    """Begin:\s{0,100}({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)""",
    """User( Name)?:\s{0,100}(({user_fullname}[^,\s]{1,2000}(\s{1,100}[^,\s]{1,2000})+)|(none|({user}[^,]{1,2000}))),""",
    """Domain:(?:\s{1,100}|\s{0,100}({domain}[^,]{1,2000})),""",
    """Application:(?:\s{1,100}|\s{0,100}({process}({directory}(?:[^,]{1,2000})?[\\\/])?({process_name}[^\\\/,]{1,2000}?))),""",
    """CIDS Signature ID:\s{0,100}({alert_name}\d{1,100}),""",
    """Intrusion ID:\s{0,100}({alert_id}\d{1,100}),""",
    """CIDS Signature string:\s{0,100}(|({alert_type}[^:,]{1,2000}?))\s{0,100}
```