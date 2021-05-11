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
  Conditions = [ """EventName=ObserveIT-DBA_Activity;""" ]
  Fields = [
    """exabeam_host=([^=]+@\s{0,100})?({host}\S+)""",
    """({host}\S+)\s{1,100}(\S+\s{1,100}){4}EventName=""",
    """\sStartTime=({time}\d\d\/\d\d\/\d\d\d\d \d\d:\d\d:\d\d)""",
    """\sOS=({os}[^;]+?)\s{0,100}(;|"{0,20}\s{0,100}$)""",
    """\sSessionID=({session_id}[^;]+?)\s{0,100}(;|"{0,20}\s{0,100}$)""",
    """\sServerName=({dest_host}[^;]+?)\s{0,100}(;|"{0,20}\s{0,100}$)""",
    """\sDomainName=({domain}[^;]+?)\s{0,100}(;|"{0,20}\s{0,100}$)""",
    """\s(?i)ViewerURL=({additional_info}[^;]+?)\s{0,100}(;|"{0,20}\s{0,100}$)""",
    """\sUserName=(?:n\/a|({user}[^;]+?))\s{0,100}(;|"{0,20}\s{0,100}$)""",
    """\sLoginName=({user}[^;]+?)\s{0,100}(;|"{0,20}\s{0,100}$)""",
    """\sSqlDBName=({database_name}[^;]+?)\s{0,100}(;|"{0,20}\s{0,100}$)""",
    """\sSqlUserName=([^;\\]+\\)?({db_user}[^;]+?)\s{0,100}(;|"{0,20}\s{0,100}$)""",
    """\sClientName=(?:\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|({src_host}[^;]+?))\s{0,100}(;|"{0,20}\s{0,100}$)""",
    """\sClientAddress=({src_ip}[a-fA-F\d.:]+)""",
    """\sProcessName=({process_name}[^;]+?)\s{0,100}(;|"{0,20}\s{0,100}$)""",
    """\sWindowTitle=({database_objects}[^;\-]+?)\s{0,100}\-[^;]*?\-\s{0,100}({app}[^;\-]+?)\s{0,100};"""
  ]
  DupFields = [ "user->os_user" , "process_name->service_name"]
}
```