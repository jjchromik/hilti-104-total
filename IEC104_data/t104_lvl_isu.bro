# @author: Justyna Chromik
# Bro file to analyse only I, S and U frame events. 
# @version: 13-04-2018


@load base/protocols/conn

module T104_Events;

export{
	redef enum Log::ID += {LOG_SetPoints};
	const DEBUG_ENABLED = T;
	const DEBUG_LEVEL = 1; 
}

function print_debug(message: string, level: int &default=1) {
	if (DEBUG_ENABLED && level>=DEBUG_LEVEL){
		print fmt("%s [DEBUG L%d] %s", strftime("%Y-%m-%d_%H:%M:%S", current_time()), level, message);
	}
}

global mode_i_counter = 0;
global mode_s_counter = 0;
global mode_u_counter = 0;
global begin_time: time;
global total_time: interval;

event bro_init() {
	begin_time = current_time();}

event t104::i (c:connection, send_seq: count, recv_seq: count) {
	mode_i_counter += 1;
}

event t104::s (c: connection, start: count, len: count, recv_seq: count) {
	mode_s_counter += 1;
}

event t104::u (c: connection){ #u_start_dt: count, u_stop_dt: count, u_test_fr: count) {
	mode_u_counter += 1;
}

event bro_done () {
	total_time =  current_time() - begin_time;
	print_debug(fmt("Total time: %s", total_time), 1);
	print_debug(fmt("mode_u_counter: %d", mode_u_counter), 1);
	print_debug(fmt("mode_s_counter: %d", mode_s_counter), 1);
	print_debug(fmt("mode_i_counter: %d", mode_i_counter), 1);
}
