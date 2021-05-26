#### Parser Content
```Java
{
Name = cef-ata-ldap-bruteforce-alert
  Vendor = Microsoft
  Product = Advanced Threat Analytics (ATA)
  Lms = Splunk
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSSZ"
  Conditions = [ """|Microsoft|ATA|""", """|LdapBruteForceSuspiciousActivity|""", """CEF:""" ]
  Fields = [
    """exabeam_host=([^=@]{1,2000}@)?({host}[\w.\-]{1,2000})""",
    """Auth\.[^\s]{1,2000}\s{0,100}({host}[^\s]{1,2000})""",
    """CEF:([^\|]{0,2000}\|){4}({alert_type}[^\|]{1,2000})\|({alert_name}[^\|]{1,2000})\|({alert_severity}[^\|]{1,2000})\|""",
    """start=({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}Z)""",
    """msg=({additional_info}[^=]{1,2000}?)\s{1,100}(\w+=|$)""",
    """msg=[^=]{0,2000}? from (?:({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({src_host}[^\.\s]{1,2000}))""",
    """cs1=({additional_info}[^=]{1,2000}?)\s{0,100}"{0,20}(\w+=|$)"""
  ]
}
```