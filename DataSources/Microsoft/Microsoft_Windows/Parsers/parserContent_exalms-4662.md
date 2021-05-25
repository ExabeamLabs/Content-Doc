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
    """"@timestamp"\s{0,100}:\s{0,100}"({time}.+?)"""",
    """"(?:winlog\.)?computer_name"\s{0,100}:\s{0,100}"({host}.+?)"""",
    """ObjectServer":"({object_class}.+?)"""",
    """ObjectName":"({object}[^"]{1,2000})"""",
    """ObjectType":"({object_type}.+?)"""",
    """SubjectUserName":"({user}.+?)"""",
    """SubjectLogonId":"({logon_id}[^"]{1,2000})"""",
    """SubjectDomainName":"({domain}[^"]{1,2000})"""",
    """OperationType":"({action}[^"]{1,2000})"""",
    """Properties":"({properties}[^"]{1,2000})"""",
    """"AdditionalInfo"{1,20}:"{1,20}(-|({attribute}[^"]{1,2000}))"""",
    """"keywords":\["({outcome}[^"]{1,2000})"\]""",
    """({event_code}4662)"""
  ]
  DupFields = [ "host->dest_host" ]
}
```