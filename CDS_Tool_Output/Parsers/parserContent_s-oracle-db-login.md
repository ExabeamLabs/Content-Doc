#### Parser Content
```Java
{
Name = s-oracle-db-login
    Vendor = Oracle
    Lms = Splunk
    DataType = "database-login"
    IsHVF = true
    TimeFormat = "yyyy-MM-dd HH:mm:ss"
    Conditions = [ """ACTION_NAME="LOGON"""", """ACTION="100"""", """HOST_NAME""" ]
    Fields = [
      """\sTIMESTAMP="+({time}\d{4}\-\d\d\-\d\d \d\d:\d\d:\d\d)""",
      """\sHOST_NAME="+({host}[^"]+)""",
      """\sUSERNAME="+({user}[^"]+)""",
      """\sDB_NAME="+({database_name}[^"]+)""",
      """\(HOST=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
      """\sUSERHOST="+([^\\]+\\)?({src_host}[^"]+)"""
    ]
  }
```