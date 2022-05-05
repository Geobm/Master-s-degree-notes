
def set_Bin(num, num_bits):
	mod = int(2**num_bits)
	new_num = num ^ mod
	cad = bin(new_num)[3:]
	return cad

def set_Hex(num, num_bits):
	mod = int(2**num_bits)
	new_num = num ^ mod
	cad = hex(new_num)[3:]
	return cad


def permutation(num):
	binary_number = set_Bin(num,8)

	#49 this value depends on the table
	indexes = [i + 49 for i, x in enumerate(binary_number) if x == "1"]

	# 32 - 4 (beginning) = 28 = half secret key
	result = ["0"]*32

	for index in indexes:
		try:
			bit_on = pc_2_der.index(index)
		except ValueError:
			pass
		else:
			result[bit_on] = "1"	
		
	result = ''.join(str(e) for e in result)

	return "0x" + set_Hex(int(result,2),32)


if __name__ == "__main__":
	
	list_1 = []
	for num in range(0,256):
		list_1.append(permutation(num))

	for i in range(0,256,8):
		print(list_1[i:i+8])







