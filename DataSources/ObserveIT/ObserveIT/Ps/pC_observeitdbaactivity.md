#### Parser Content
```Java
{
Name = observeit-dba-activity
  Vendor = ObserveIT
  Product = ObserveIT
  Lms = Direct
  DataType = "database-access"
  IsHVF = true
  TimeFormat = "MM/dd/yyyy HH:mm:ss"
  Conditions = [ """EventName =ObserveIT-DBA_Activity;""" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """({host}\S+)\s{1,100}(\S+\s{1,100}){4}EventName =""",
    """\sStartTime=({time}\d\d\/\d\d\/\d\d\d\d \d\d:\d\d:\d\d)""",
    """\sOS=({os}[^;]{1,2000}?)\s{0,100}(;|"{0,20}\s{0,100}$)""",
    """\sSessionID=({session_id}[^;]{1,2000}?)\s{0,100}(;|"{0,20}\s{0,100}$)""",
    """\sServerName =({dest_host}[^;]{1,2000}?)\s{0,100}(;|"{0,20}\s{0,100}$)""",
    """\sDomainName =({domain}[^;]{1,2000}?)\s{0,100}(;|"{0,20}\s{0,100}$)""",
    """\s(?i)ViewerURL=({additional_info}[^;]{1,2000}?)\s{0,100}(;|"{0,20}\s{0,100}$)""",
    """\sUserName =(?:n\/a|({user}[^;]{1,2000}?))\s{0,100}(;|"{0,20}\s{0,100}$)""",
    """\sLoginName =({user}[^;]{1,2000}?)\s{0,100}(;|"{0,20}\s{0,100}$)""",
    """\sSqlDBName =({database_name}[^;]{1,2000}?)\s{0,100}(;|"{0,20}\s{0,100}$)""",
    """\sSqlUserName =([^;\\]{1,2000}\\)?({db_user}[^;]{1,2000}?)\s{0,100}(;|"{0,20}\s{0,100}$)""",
    """\sClientName =(?:\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|({src_host}[^;]{1,2000}?))\s{0,100}(;|"{0,20}\s{0,100}$)""",
    """\sClientAddress=({src_ip}[a-fA-F\d.:]{1,2000})""",
    """\sProcessName =({process_name}[^;]{1,2000}?)\s{0,100}(;|"{0,20}\s{0,100}$)""",
    """\sWindowTitle=({database_objects}[^;\-]{1,2000}?)\s{0,100}\-[^;]{0,2000}?\-\s{0,100}({app}[^;\-]{1,2000}?)\s{0,100};"""
  ]
  DupFields = [ "user->os_user" , "process_name->service_name"]


}
```