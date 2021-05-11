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
    """exabeam_host=([^=@]+@)?({host}[\w.\-]+)""",
    """Auth\.[^\s]+\s{0,100}({host}[^\s]+)""",
    """CEF:([^\|]*\|){4}({alert_type}[^\|]+)\|({alert_name}[^\|]+)\|({alert_severity}[^\|]+)\|""",
    """start=({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}Z)""",
    """msg=({additional_info}[^=]+?)\s{1,100}(\w+=|$)""",
    """msg=[^=]*? from (?:({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({src_host}[^\.\s]+))""",
    """cs1=({additional_info}[^=]+?)\s{0,100}"{0,20}(\w+=|$)"""
  ]
}
```