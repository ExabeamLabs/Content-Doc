#### Parser Content
```Java
{
Name = msnetwork-nac-logon-5
  Vendor = Microsoft
  Product = Microsoft NPS
  Lms = Direct
  DataType = "windows-nac-logon"
  TimeFormat = "MM/dd/yyyy,HH:mm:ss"
  Conditions = [ ""","IAS",""", """",2,"""" ]
  Fields = [
    """({host}[^"]{1,2000})","IAS",({time}\d\d\/\d\d\/\d\d\d\d,\d\d:\d\d:\d\d),(|({outcome}\d{1,100})),(|"({user}[^"]{1,2000})"),([^,]{0,2000

}
```