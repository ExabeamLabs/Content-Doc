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
    """Local:\s{0,100}({dest_ip}[a-fA-F:\.\d]+),(Local:\s{0,100}(?:0+|({dest_host}[^,]+)))?.*?,Inbound,""",
    """Remote:\s{0,100}({src_ip}[a-fA-F:\.\d]+),(Remote:\s{0,100}(?:0+|({src_host}[^,]+)))?.*?,Inbound,""",
    """Local:\s{0,100}({src_ip}[a-fA-F:\.\d]+),(Local:\s{0,100}(?:0+|({src_host}[^,]+)))?.*?,Outbound,""",
    """Remote:\s{0,100}({dest_ip}[a-fA-F:\.\d]+),(Remote:\s{0,100}(?:0+|({dest_host}[^,]+)))?.*?,Outbound,""",
    """Remote Host Name:\s{0,100}(|({src_host}[\w\-.]+)),(Remote Host IP:\s{0,100}(?:0+|({src_ip}[A-Fa-f:\d.]+)),)?.*?,Inbound,""",
    """Remote Host Name:\s{0,100}(|({dest_host}[\w\-.]+)),(Remote Host IP:\s{0,100}(?:0+|({dest_ip}[A-Fa-f:\d.]+)),)?.*?,Outbound,""",
    """Local Host IP:\s{0,100}({src_ip}[a-fA-F\d.:]+).*?,Outbound,""",
    """Local Host IP:\s{0,100}({dest_ip}[a-fA-F\d.:]+).*?,Inbound,""",
    """Begin:\s{0,100}({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)""",
    """User( Name)?:\s{0,100}(({user_fullname}[^,\s]+(\s{1,100}[^,\s]+)+)|(none|({user}[^,]+))),""",
    """Domain:(?:\s{1,100}|\s{0,100}({domain}[^,]+)),""",
    """Application:(?:\s{1,100}|\s{0,100}({process}({directory}(?:[^,]+)?[\\\/])?({process_name}[^\\\/,]+?))),""",
    """CIDS Signature ID:\s{0,100}({alert_name}\d{1,100}),""",
    """Intrusion ID:\s{0,100}({alert_id}\d{1,100}),""",
    """CIDS Signature string:\s{0,100}(|({alert_type}[^:,]+?))\s{0,100}
```