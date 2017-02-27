# NetFuzzer
![image](https://github.com/weizn11/NetFuzzer/raw/master/img/flow.jpg)
<br><br><br>
所有callback函数：<br>
ex_send_callback()                #自定义发送函数<br>
connect_failed_callback()         #连接失败回调函数<br>
connect_success_callback()        #连接成功回调函数<br>
send_failed_callback()            #发送失败回调函数<br>
pre_mutate_callback()             #测试用例生成前回调函数<br>
post_mutate_callback()            #测试用例生成后回调函数<br>
start_wait_callback()             #开始Fuzz前回调函数<br>
fetch_proc_crash_callback()       #在进程监视器中获取进程到crash信息回调<br>
detected_target_crash_callback()  #通过网络监视器获取到目标crash信息回调<br>
custom_detect_crash_callback()    #自定义检测目标crash方法的回调函数<br>
pre_send_callback()               #测试用例发送前的回调函数<br>
post_send_callback()              #测试用例发送完成后的回调函数<br>
packet_handler_callback()         #网络嗅探器抓取到的数据包回调处理函数<br>
<br><br>
