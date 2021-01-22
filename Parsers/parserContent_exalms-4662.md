#### Parser Content
```Java
{
Name = exalms-4662
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "object-access"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = ["""@timestamp":""", """An operation was performed on an object""" , """ObjectName""", """computer_name"""]
  Fields = [
    """({event_name}An operation was performed on an object)""",
    """"@timestamp"\s*:\s*"({time}.+?)"""",
    """"computer_name"\s*:\s*"({host}.+?)"""",
    """ObjectServer":"({object_class}.+?)"""",
    """ObjectName":"({object}[^"]+)"""",
    """ObjectType":"({activity_type}.+?)"""",
    """SubjectUserName":"({user}.+?)"""",
    """SubjectLogonId":"({logon_id}[^"]+)"""",
    """SubjectDomainName":"({domain}[^"]+)"""",
    """OperationType":"({action}[^"]+)"""",
    """Properties":"({properties}[^"]+)"""",
    """Additional\s*Information:({attribute}[^"]+)""""
    """"keywords":\["({outcome}[^"]+)"\]""",
    """({event_code}4662)"""
  ]
  DupFields = [ "host->dest_host" ]
}
```