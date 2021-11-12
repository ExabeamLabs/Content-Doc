#### Parser Content
```Java
{
Name = trapx-network-alert-1
  DataType = "network-alert"
  Conditions = [ """|TrapX|TSOC|""", """|TOR Node Access|""","""proto=""" ]
}
trapx-alert = {
    Vendor = TrapX
    Product = TrapX
    Lms = Splunk
    TimeFormat = "MMM dd yyyy HH:mm:ss"
    Fields = [
      """rt=({time}\w{3}\s\d\d\s\d\d\d\d\s\d\d:\d\d:\d\d)\s""",
      """exabeam_host=({host}[^\s]{1,2000})""",
      """\d\d\s({host}[\w\-.]{1,2000})\sCEF:""",
      """CEF:([^|]{0,2000}\|){6}({alert_severity}[^|]{1,2000})""",
      """CEF:([^|]{0,2000}\|){5}({alert_type}[^|]{1,2000})""",
      """CEF:([^|]{0,2000}\|){4}ID:({event_code}\d{1,100})""",
      """cat=({alert_name}[^=]{1,2000}?)\s\w+=""",
      """externalId=({alert_id}\d{1,100})""",
      """src=({src_ip}[A-Fa-f\d:.]{1,2000})""",
      """dst=({dest_ip}[A-Fa-f\d:.]{1,2000})""",
      """dpt=({dest_port}\d{1,100})""",
      """deviceNtDomain=({domain}[^=]{1,200})\s\w+=""",
      """proto=({protocol}[^=]{1,2000})\s\w+="""
    ]}
```