#### Parser Content
```Java
{
Name = symantec-dlp-alert
  Vendor = Symantec
  Product = Symantec DLP
  Lms = Direct
  DataType = "dlp-alert"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """, violatedPolicyRuleName: """, """,[CA Name: Risk Severity],""", """,[CA Name: SIFT Timestamp],""" ]
  Fields = [
    """\[CA Name: SIFT Timestamp\], \[CA value:\s*({time}\d+-\d+-\d+\s+\d+:\d+:\d+)""",
    """\[CA Name: Detection Server\], \[CA value:\s*({host}[\w\-.]+)""",
    """\[CA Name: First Name\], \[CA value:\s*(|({user_firstname}[^\]]+?))\s*\]""",
    """\[CA Name: Last Name\], \[CA value:\s*({user_lastname}[^\]]+)""",
    """\[CA Name: Account Name\], \[CA value:\s*({user}[^\]\s]+)""",
    """\[CA Name: Email\], \[CA value:\s*({user_email}[^\]\s@]+@[^\]\s@]+)""",
    """\[CA Name: Risk Severity\], \[CA value:\s*(|({alert_severity}[^\]]+?))\s*\]""",
    """, violatedPolicyRuleName:\s*({alert_name}[^\],]+?)\s*,""",
  ]
  DupFields = [ "alert_name->alert_type" ]
}
```