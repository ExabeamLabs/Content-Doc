#### Parser Content
```Java
{
Name = cimtrak-file-write-2
  Conditions = [ """CTK:""", """|Cimcor|CimTrak|""", """|File Modified|""" ]
}
cimtrak-file-operations {
  Vendor = Cimtrak
  Product = Cimtrak
  Lms = Direct
  DataType = "file-operations"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Fields = [
    """\s({host}[\w\-.]{1,2000})\s{1,100}CTK:""",
    """eventTime=({time}\d{1,100}-\d{1,100}-\d{1,100}\s{1,100}\d{1,100}:\d{1,100}:\d{1,100})""",
    """CTK:([^\|]{0,2000}\|){5}({accesses}[^\|]{1,2000})""",
    """cimtrakUser=({user}[^\s]{1,2000})""",
    """filePath=(|({file_path}({file_parent}[^"]{0,2000}?)[\\\/]{0,2000}({file_name}[^\\\/"]{1,2000}?(\.({file_ext}[^\\\/\.\s"]{1,2000}))?)))\s{1,100}(\w+=|$)""",
    """processName =(|({process}({directory}.*?)(\/+({process_name}[^\/]{1,2000}?))?))\s{1,100}(\w+=|$)""",
    """processID=({process_id}[^\s]{1,2000})""",
  ]}
```