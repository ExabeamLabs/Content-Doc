#### Parser Content
```Java
{
Name = code42-file-operations-4
  Vendor = Code42
  Product = Code42 Incydr
  Lms = Direct
  DataType = "file-operations"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions= [ """"fileCategoryByExtension"""",  """"eventType"""", """"osHostName"""]
  Fields = [ 
    """exabeam_host=([^=]+@\s{0,100})?({host}\S+)""",
    """"eventType"{1,20}:\s{0,100}"{1,20}({accesses}MODIFIED|DELETED|READ|CREATED)""",
    """"mimeTypeByExtension"{1,20}:\s{0,100}"{1,20}({mime}[^"]+)"""",
    """"tabUrl"{1,20}:\s{0,100}"{1,20}({full_url}[^"]+)"""",
    """"exposure"{1,20}:\s{0,100}\["{0,20}({log_source}[^"\]]+)"{0,20}\]""",
    """"processName"{1,20}:\s{0,100}"{1,20}({process_name}[^"]+)"""",
    """"userUid"{1,20}:\s{0,100}"{1,20}({user_uid}[^"]+)"""",
    """"deviceUid"{1,20}:\s{0,100}"{1,20}({device_id}[^"]+)"""",
    """"publicIpAddress"{1,20}:\s{0,100}"{1,20}({src_ip}[^"]+)"""",
    """"domainName"{1,20}:\s{0,100}"{1,20}({domain}[^"]+)"""",
    """"eventTimestamp"{1,20}:\s{0,100}"{1,20}({time}[^"]+)"""",
    """"filePath"{1,20}:\s{0,100}"{1,20}({file_path}[^"]+)"""",
    """"fileName"{1,20}:\s{0,100}"{1,20}({file_name}[^"]+)"""",
    """"fileCategory"{1,20}:\s{0,100}"{1,20}({file_type}[^"]+)"""",
    """"fileCategoryByExtension"{1,20}:\s{0,100}"{1,20}({file_ext}[^"]+)"""",
    """"fileSize"{1,20}:\s{0,100}({file_size}\d{1,100})""",
    """"processOwner"{1,20}:\s{0,100}"{1,20}({user}[^"]+)"""",
    """"md5Checksum"{1,20}:\s{0,100}"{1,20}({md5}[^"]+)"""",
    """"sha256Checksum"{1,20}:\s{0,100}"{1,20}({sha256}[^"]+)"""",
    """"deviceUserName"{1,20}:\s{0,100}"{1,20}({user_email}[^"]+)"""",
    """"osHostName"{1,20}:\s{0,100}"{1,20}({dest_host}[^"]+)"""",
    """"windowTitle"{1,20}:\s{0,100}\["{0,20}({service}[^"\]]+)"{0,20}\]""",
    """"actor"{1,20}:"{1,20}(({user_email}[^"@]+@[^"@]+)|({user}[^"]+))""",
  ]
  DupFields = ["file_path->file_parent", "dest_host->device_name"]
}
```