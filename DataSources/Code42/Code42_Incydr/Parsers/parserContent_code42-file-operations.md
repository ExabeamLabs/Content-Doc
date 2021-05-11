#### Parser Content
```Java
{
Name = code42-file-operations
  Vendor = Code42
  Product = Code42 Incydr
  Lms = Direct
  DataType = "file-operations"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions= [ """Code42LogCollector,""", """KAFKA_CONNECT_SYSLOG: """]
  Fields = [
    """KAFKA_CONNECT_SYSLOG:\s{1,100}({host}[^,]+),(|("{1,20}({event_code}[^"]+)"{1,20})|({=event_code}[^,]+)),(|("{1,20}({accesses}[^"]+)"{1,20})|({=accesses}[^,]+)),(|("{1,20}({time}[^"]+)"{1,20})|({=time}[^,]+)),(|("{1,20}[^"]+"{1,20})|[^,]+),(|("{1,20}({file_path}[^"]+)"{1,20})|({=file_path}[^,]+)),(|("{1,20}({file_name}[^"]+)"{1,20})|({=file_name}[^,]+?(\.({file_ext}[^\.,]+))?)),(|("{1,20}[^"]+"{1,20})|[^,]+),(|("{1,20}({file_type}[^"]+)"{1,20})|({=file_type}[^,]+)),(|("{1,20}({bytes}[^"]+)"{1,20})|({=bytes}[^,]+)),(|("{1,20}[^"]+"{1,20})|[^,]+),(|("{1,20}({md5}[^"]+)"{1,20})|({=md5}[^,]+)),(|("{1,20}({sha256}[^"]+)"{1,20})|({=sha256}[^,]+)),(|("{1,20}({time_created}[^"]+)"{1,20})|({=time_created}[^,]+)),(|("{1,20}({time_modified}[^"]+)"{1,20})|({=time_modified}[^,]+)),(|("{1,20}({user_email}[^"]+)"{1,20})|({=user_email}[^,]+)),(|("{1,20}[^"]+"{1,20})|[^,]+),(|("{1,20}({user_uid}[^"]+)"{1,20})|({=user_uid}[^,]+)),(|("{1,20}({src_host}[^"]+)"{1,20})|({=src_host}[^,]+)),(|("{1,20}[^"]+"{1,20})|[^,]+),(|("{1,20}({src_ip}[^"]+)"{1,20})|({=src_ip}[^,]+)),(|("{1,20}({additional_info}[^"]+)"{1,20})|({=additional_info}[^,]+)),(|("{1,20}({actor}[^"]+)"{1,20})|({=actor}[^,]+)),(|("{1,20}({directory_id}[^"]+)"{1,20})|({=directory_id}[^,]+)),(|("{1,20}({app}[^"]+)"{1,20})|({=app}[^,]+)),(|("{1,20}({full_url}[^"]+)"{1,20})|({=full_url}[^,]+)),(|("{1,20}({shared}[^"]+)"{1,20})|({=shared}[^,]+)),(|("{1,20}({shared_with}[^"]+)"{1,20})|({=shared_with}[^,]+)),(|("{1,20}({file_exposure_changed_to}[^"]+)"{1,20})|({=file_exposure_changed_to}[^,]+)),(|("{1,20}({cloud_drive_id}[^"]+)"{1,20})|({=cloud_drive_id}[^,]+)),(|("{1,20}({detection_source_alias}[^"]+)"{1,20})|({=detection_source_alias}[^,]+)),(|("{1,20}({file_id}[^"]+)"{1,20})|({=file_id}[^,]+)),(?:|("{1,20}({exposure_type}[^"]+)"{1,20})|({=exposure_type}[^,]+)),(|("{1,20}({process_owner}[^"]+)"{1,20})|({=process_owner}[^,]+)),(|("{1,20}({process_name}[^"]+)"{1,20})|({=process_name}[^,]+)),(|("{1,20}({device_vendor}[^"]+)"{1,20})|({=device_vendor}[^,]+)),(|("{1,20}({device_name}[^"]+)"{1,20})|({=device_name}[^,]+)),(|("{1,20}({device_id}[^"]+)"{1,20})|({=device_id}[^,]+)),(|("{1,20}({device_size}[^"]+)"{1,20})|({=device_size}[^,]+)),(|("{1,20}({device_type}[^"]+)"{1,20})|({=device_type}[^,]+)),(|("{1,20}({sync_destination}[^"]+)"{1,20})|({=sync_destination}[^,]+))"""
]
  DupFields = ["file_path->file_parent"]
}
```