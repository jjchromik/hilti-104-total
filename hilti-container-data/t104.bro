@load base/protocols/conn

export {
	
	type norm_val:record {
		ioa_addr: int;
		value: int;
	};

	type results: record {
		results_norm: vector of norm_val;

	};
}


global apci_counter = 0;
global tcp_apci_counter = 0;
global mode_i_counter = 0;
global mode_s_counter = 0;
global mode_u_counter = 0;
global m_sp_na_counter = 0;
global m_sp_ta_counter = 0;
global m_me_na_counter = 0;
global m_sp_tb_counter = 0;
global m_me_td_counter = 0;
global c_se_ta_counter = 0;
global c_sc_ta_counter = 0;
global c_ic_na_counter = 0;
global c_ci_na_counter = 0;
global c_cs_na_counter = 0;
global c_ts_ta_counter = 0;
global c_ih_na_p_counter = 0;
global c_su_na_p_counter = 0;
global x_ds_na_p_counter = 0;

event bro_init() {
	print "bro_init";
}

event t104::apci (c: connection, len: int, mode: int, i_send_seq: int, u_start_dt: int, u_stop_dt: int, u_test_fr: int, recv_seq: int) {
	#print "APCI", c$id$orig_h, c$id$resp_h, "len", len,"mode", mode, "i_send_seq", i_send_seq,"u_start_dt", u_start_dt,"u_stop_dt", u_stop_dt,"u_test_fr", u_test_fr,"recv_seq", recv_seq;
	apci_counter = apci_counter + 1;
}

type cause:record {
	#cot : count;
    negative : bool;
    test : bool;
    #info_obj_type : string;
    common_addr : int;
    #cot : int;
};



event t104::i (c:connection, send_seq: count, recv_seq: count) {
	mode_i_counter += 1;
}

event t104::s (c: connection, start: count, len: count, recv_seq: count) {
	mode_s_counter += 1;
}

event t104::u (c: connection){ #u_start_dt: count, u_stop_dt: count, u_test_fr: count) {
	mode_u_counter += 1;
}
#1
event t104::m_sp_na_1(c: connection, cot: cause) {
	m_sp_na_counter += 1;
}
#2
event t104::m_sp_ta_1(c: connection, cot: cause) {
	m_sp_ta_counter += 1;
}
#9
event t104::m_me_na_1(c: connection, cot: cause) {
	m_me_na_counter += 1;
}
#30
event t104::m_sp_tb_1(c: connection, cot: cause) {
	m_sp_tb_counter += 1;
}
#34
event t104::m_me_td_1(c: connection, cot: norm_val) { # list of tuples: address: value
	#print cot$ioa_addr;
	#local outcome:double = cot$value/32768.0;
	#print outcome;
	m_me_td_counter += 1;
}
#58
event t104::c_sc_ta_1(c: connection, cot: cause) {
	c_sc_ta_counter += 1;
}
#61
event t104::c_se_ta_1(c: connection, ioa: norm_val) { #norm_val
	print ioa$ioa_addr;
	print "Value:", ioa$value/32768.0;
	c_se_ta_counter += 1;
}
#100
event t104::c_ic_na_1(c: connection, cot: cause) {
	c_ic_na_counter += 1;
}
#101
event t104::c_ci_na_1(c: connection, cot: cause) {
	c_ci_na_counter += 1;
}
#103
event t104::c_cs_na_1(c: connection, cot: cause) {
	c_cs_na_counter += 1;
}
#107
event t104::c_ts_ta_1(c: connection, cot: cause) {
	c_ts_ta_counter += 1;
}
#142
event t104::c_ih_na_p(c: connection, cot: cause) {
	c_ih_na_p_counter += 1;
}
#143
event t104::c_su_na_p(c: connection, cot: cause) {
	c_su_na_p_counter += 1;
}
#200 
event t104::x_ds_na_p(c: connection, cot: cause) {
	x_ds_na_p_counter += 1;
}




#######################################
# 		STUFF FOR TESTING			  # 
#######################################

#event tcp_packet(c: connection, is_orig: bool, flags: string, seq:count, ack: count, len: count, payload: string) {
#	print "Length: ", len;
#	print "TCP packet payload: ", payload;
#}

#event t104::asdu (c: connection, cot: cause, info_obj_type: T104::Info_obj_code) {#, cause_of_transmission: T104::Cot_code) {
#	asdu_counter += 1;
#}

#event connection_established (c: connection){
#	print "TCP connection_established", c$id$orig_h, c$id$resp_h, c$id$orig_p, c$id$resp_p, c$service;
#}

#event connection_state_remove(c: connection) {
	#print "TCP connection_state_remove", c$id$orig_h, c$id$resp_h, c$id$orig_p, c$id$resp_p, c$service;
#}

event bro_done () {
	print "apci_counter", apci_counter;
	print "mode_u_counter", mode_u_counter;
	print "mode_s_counter", mode_s_counter;
	print "mode_i_counter", mode_i_counter;
	print "1: m_sp_na_counter", m_sp_na_counter;
	print "2: m_sp_ta_counter", m_sp_ta_counter;
	print "9: m_me_na_counter", m_me_na_counter;
	print "30: m_sp_tb_counter", m_sp_tb_counter;
	print "34: m_me_td_counter", m_me_td_counter;
	print "58: c_sc_ta_counter", c_sc_ta_counter;
	print "61: c_se_ta_counter", c_se_ta_counter;
	print "100: c_ic_na_counter", c_ic_na_counter;
	print "101: c_ci_na_counter", c_ci_na_counter;
	print "103: c_cs_na_counter", c_cs_na_counter;
	print "107: c_ts_ta_counter", c_ts_ta_counter;
	print "142: c_ih_na_p_counter", c_ih_na_p_counter;
	print "143: c_su_na_p_counter", c_su_na_p_counter;
	print "200: x_ds_na_p_counter", x_ds_na_p_counter;
}