#### Parser Content
```Java
{
Name = isi-bo-file-activity
  Vendor = BusinessObject
  Product = BusinessObject
  Lms = Splunk
  DataType = "file-activity"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd-HH.mm.ss"
  Conditions = [ """isi_bo""", """<custom_condition_cont-7495>""" ]
  Fields = [
    """"({time}\d\d\d\d-\d\d-\d\d-\d\d\.\d\d\.\d\d)[^"]*","({user}[^"]+?)","({session_id}[^"]+?)",({accesses}\d+),"(|({file_path}[^"]+?))","(-|({bytes}\d+))"""
  ]
}
```