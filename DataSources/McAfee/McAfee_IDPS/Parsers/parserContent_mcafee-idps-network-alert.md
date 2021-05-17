#### Parser Content
```Java
{
Name = mcafee-idps-network-alert
  Vendor = McAfee
  Product = McAfee IDPS
  Lms = Direct
  DataType = "network-alert"
  TimeFormat = "yyyy-MM-dd HH:mm:ss z"
  Conditions = [ """ AlertLog: |""", """|$IV_RELEVANCE$|""" ]
  Fields = [
    """\|({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d \w+)\|"({alert_name}[^"]{1,2000})"\|[^\|]{0,2000}\|(N/A|({alert_severity}[^\|]{1,2000}))(\|[^\|]{0,2000}){3}\|({host}[^\|]{1,2000})\|[^\|]{0,2000}\|(N/A|({src_ip}[^\|]{1,2000}))\|(N/A|({src_port}\d{1,100}))\|(N/A|({dest_ip}[^\|]{1,2000}))\|(N/A|({dest_port}\d{1,100}))\|({alert_type}[^\|]{1,2000}\|[^\|]{1,2000})\|({direction}[^\|]{1,2000})\|(n/a|({action}[^\|]{1,2000}))(\|[^\|]{0,2000}){2}\|(N/A|({protocol}[^\|]{1,2000}))""",
  ]
}
```