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
    """\[CA Name: Detection Server\], \[CA value:\s{0,100}({host}[\w\-.]{1,2000})""",
    """\[CA Name: First Name\], \[CA value:\s{0,100}(|({user_firstname}[^\]]{1,2000}?))\s{0,100}\]""",
    """\[CA Name: Last Name\], \[CA value:\s{0,100}({user_lastname}[^\]]{1,2000})""",
    """\[CA Name: Account Name\], \[CA value:\s{0,100}({user}[^\]\s]{1,2000})""",
    """\[CA Name: Email\], \[CA value:\s{0,100}({user_email}[^\]\s@]{1,2000}@[^\]\s@]{1,2000})""",
    """\[CA Name: Risk Severity\], \[CA value:\s{0,100}(|({alert_severity}[^\]]{1,2000}?))\s{0,100}\]""",
    """, violatedPolicyRuleName:\s{0,100}({alert_name}[^\],]{1,2000}?)\s{0,100}
```