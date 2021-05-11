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
    """\[CA Name: SIFT Timestamp\], \[CA value:\s{0,100}({time}\d{1,100}-\d{1,100}-\d{1,100}\s{1,100}\d{1,100}:\d{1,100}:\d{1,100})""",
    """\[CA Name: Detection Server\], \[CA value:\s{0,100}({host}[\w\-.]+)""",
    """\[CA Name: First Name\], \[CA value:\s{0,100}(|({user_firstname}[^\]]+?))\s{0,100}\]""",
    """\[CA Name: Last Name\], \[CA value:\s{0,100}({user_lastname}[^\]]+)""",
    """\[CA Name: Account Name\], \[CA value:\s{0,100}({user}[^\]\s]+)""",
    """\[CA Name: Email\], \[CA value:\s{0,100}({user_email}[^\]\s@]+@[^\]\s@]+)""",
    """\[CA Name: Risk Severity\], \[CA value:\s{0,100}(|({alert_severity}[^\]]+?))\s{0,100}\]""",
    """, violatedPolicyRuleName:\s{0,100}({alert_name}[^\],]+?)\s{0,100}
```