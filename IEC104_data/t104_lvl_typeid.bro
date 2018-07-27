# @author: Justyna Chromik
# Bro file to analyse various TypeIDs frame events. 
# @version: 13-04-2018

@load base/protocols/conn

module T104_Events;

export{
	redef enum Log::ID += {LOG_SetPoints};
	#redef PacketFilter::all_packets=T;
	const DEBUG_ENABLED = T;
}

function print_debug(message: string) {
	if (DEBUG_ENABLED){
		print fmt("%s [DEBUG] %s", strftime("%Y-%m-%d_%H:%M:%S", current_time()), message);
	}
}

export {
	type norm_val:record {
		ioa_addr: int;
		value: int;
	};
	type single_point:record {
		ioa_addr: int;
		point: bool;
	};
}

global m_sp_na_counter = 0;
global m_dp_na_counter = 0;
global m_st_na_counter = 0;
global m_me_na_counter = 0;
global m_sp_tb_counter = 0;
global m_me_td_counter = 0;
global c_se_na_counter = 0;
global c_se_ta_counter = 0;
global c_sc_ta_counter = 0;
global m_ei_na_counter = 0;
global c_ic_na_counter = 0;
global c_ci_na_counter = 0;
global c_cs_na_counter = 0;
global c_ts_ta_counter = 0;
global c_ih_na_p_counter = 0;
global c_su_na_p_counter = 0;
global x_ds_na_p_counter = 0;
global test_counter = 0;

global begin_time: time;
global total_time: interval;

event bro_init() {
	begin_time = current_time();

}

type cause:record {
    negative : bool;
    test : bool;
    common_addr : int;
};

##############################
###       TYPE IDs         ###
##############################
#1
#event t104::m_dp_na_asdu(c: connection, cot: cause) {
#	test_counter += 1;
#}

#1
event t104::m_sp_na_asdu(c: connection, cot: cause) {
	m_sp_na_counter += 1;
}
#3
event t104::m_dp_na_asdu(c: connection, cot: cause) {
	m_dp_na_counter += 1;
}
#5 
event t104::m_st_na_asdu(c: connection, cot: cause) {
	m_st_na_counter += 1;
}
#9
event t104::m_me_na_asdu(c: connection, cot: cause) {
	m_me_na_counter += 1;
}
#30
event t104::m_sp_tb_asdu(c: connection, cot: cause) {
	m_sp_tb_counter += 1;
}
#34
event t104::m_me_td_asdu(c: connection, cot: cause) { 
	m_me_td_counter += 1;
}
#48
event t104::c_se_na_asdu(c: connection, cot: cause) {
	c_se_na_counter += 1;
}
#58
event t104::c_sc_ta_asdu(c: connection, cot: cause) {
	c_sc_ta_counter += 1;
}
#61
event t104::c_se_ta_asdu(c: connection, cot: cause) { 
	c_se_ta_counter += 1;
}
#61
event t104::m_ei_na_asdu(c: connection, cot: cause) { 
	m_ei_na_counter += 1;
}
#100
event t104::c_ic_na_asdu(c: connection, cot: cause) {
	c_ic_na_counter += 1;
}
#101
event t104::c_ci_na_asdu(c: connection, cot: cause) {
	c_ci_na_counter += 1;
}
#103
event t104::c_cs_na_asdu(c: connection, cot: cause) {
	c_cs_na_counter += 1;
}
#107
event t104::c_ts_ta_asdu(c: connection, cot: cause) {
	c_ts_ta_counter += 1;
}
#142
event t104::c_ih_na_p_asdu(c: connection, cot: cause) {
	c_ih_na_p_counter += 1;
}
#143
event t104::c_su_na_p_asdu(c: connection, cot: cause) {
	c_su_na_p_counter += 1;
}
#200 
event t104::x_ds_na_p_asdu(c: connection, cot: cause) {
	x_ds_na_p_counter += 1;
}


event bro_done () {
	total_time =  current_time() - begin_time;
	print_debug(fmt("Total time: %s", total_time));
	print_debug(fmt("1: m_sp_na_counter: %d", m_sp_na_counter));
	print_debug(fmt("3: m_dp_na_counter: %d", m_dp_na_counter));
	print_debug(fmt("5: m_st_na_counter: %d", m_st_na_counter));
	print_debug(fmt("9: m_me_na_counter: %d", m_me_na_counter));
	print_debug(fmt("30: m_sp_tb_counter: %d", m_sp_tb_counter));
	print_debug(fmt("34: m_me_td_counter: %d", m_me_td_counter));
	print_debug(fmt("48: c_se_na_counter: %d", c_se_na_counter));
	print_debug(fmt("58: c_sc_ta_counter: %d", c_sc_ta_counter));
	print_debug(fmt("61: c_se_ta_counter: %d", c_se_ta_counter));
	print_debug(fmt("70: m_ei_na_counter: %d", m_ei_na_counter));
	print_debug(fmt("100: c_ic_na_counter: %d", c_ic_na_counter));
	print_debug(fmt("101: c_ci_na_counter: %d", c_ci_na_counter));
	print_debug(fmt("103: c_cs_na_counter: %d", c_cs_na_counter));
	print_debug(fmt("107: c_ts_ta_counter: %d", c_ts_ta_counter));
	print_debug(fmt("142: c_ih_na_p_counter: %d", c_ih_na_p_counter));
	print_debug(fmt("143: c_su_na_p_counter: %d", c_su_na_p_counter));
	print_debug(fmt("200: x_ds_na_p_counter: %d", x_ds_na_p_counter));
	print_debug(fmt("test: test_coutner: %d", test_counter));
	
}
