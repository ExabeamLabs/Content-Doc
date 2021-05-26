#### Parser Content
```Java
{
Name = symantec-epp-alert-japanese
  Vendor = Symantec
  Product = Symantec Endpoint Protection
  Lms = Direct
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """,SHA-256:""", """,MD-5:""", """,CIDS シグネチャ文字列:""", """,アプリケーション:""", """シグネチャ ID:""" ]
  Fields = [
    """({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d),[^,]{0,2000}
```