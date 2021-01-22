#### Parser Content
```Java
{
Name = code42-file-operations-4
  Vendor = Code42
  Product = Code42
  Lms = Direct
  DataType = "file-operations"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions= [ """"fileCategoryByExtension"""",  """"eventType"""", """"osHostName"""]
  Fields = [ 
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """"eventType"+:\s*"+({accesses}MODIFIED|DELETED|READ|CREATED)""",
    """"mimeTypeByExtension"+:\s*"+({mime}[^"]+)"""",
    """"tabUrl"+:\s*"+({full_url}[^"]+)"""",
    """"exposure"+:\s*\["*({source}[^"\]]+)"*\]""",
    """"processName"+:\s*"+({process_name}[^"]+)"""",
    """"userUid"+:\s*"+({user_uid}[^"]+)"""",
    """"deviceUid"+:\s*"+({device_id}[^"]+)"""",
    """"publicIpAddress"+:\s*"+({src_ip}[^"]+)"""",
    """"domainName"+:\s*"+({domain}[^"]+)"""",
    """"eventTimestamp"+:\s*"+({time}[^"]+)"""",
    """"filePath"+:\s*"+({file_path}[^"]+)"""",
    """"fileName"+:\s*"+({file_name}[^"]+)"""",
    """"fileCategory"+:\s*"+({file_type}[^"]+)"""",
    """"fileCategoryByExtension"+:\s*"+({file_ext}[^"]+)"""",
    """"fileSize"+:\s*({file_size}\d+)""",
    """"processOwner"+:\s*"+({user}[^"]+)"""",
    """"md5Checksum"+:\s*"+({md5}[^"]+)"""",
    """"sha256Checksum"+:\s*"+({sha256}[^"]+)"""",
    """"deviceUserName"+:\s*"+({user_email}[^"]+)"""",
    """"osHostName"+:\s*"+({dest_host}[^"]+)"""",
    """"windowTitle"+:\s*\["*({service}[^"\]]+)"*\]""",
  ]
  DupFields = ["file_path->file_parent", "dest_host->device_name"]
}
```