#Created by Geovani Benita
#TCP segmentation and graph
import matplotlib.pyplot as plt
import numpy as np
tcp_h, ip_h, llc_h, mac_h =  20, 20 , 3, 18
count, payload, efficacy = 0, 0, 0
list_eff, tcp = [], []
for i in range (0,5000,5):
  message = i
  if message > 1024: 
    last_long_payload = message%1024
    remaining_payloads = message - last_long_payload
    count = (remaining_payloads/1024)
    last_long_payload_result = last_long_payload + tcp_h + ip_h + llc_h + mac_h 
    final = (((tcp_h + ip_h + llc_h + mac_h)*count)+ remaining_payloads + last_long_payload_result) 
    efficacy = message / final
    list_eff.append(efficacy*100)
    list_eff1 = message / final 
    #print("The efficacy of a packet with {} bytes is {} ".format(i,efficacy*100))
  else:
    payload = message + tcp_h + ip_h + llc_h + mac_h
    efficacy = message / payload
    list_eff.append(efficacy*100)  
    #print("The efficacy of a packet with {} bytes is {} ".format(i,efficacy*100))
x = np.arange(0,5000,5)
y = list_eff
y1 = list_eff1
colors=['orange', 'purple', 'green','red']

plt.gca().set_prop_cycle(color=colors)
plt.plot(x,y)
plt.xlabel('Message (bytes)')
plt.ylabel('Efficacy %')
plt.title('Efficacy vs message')
plt.show()
#print(len(list_eff))