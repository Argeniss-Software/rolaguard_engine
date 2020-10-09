# LoRaWAN Security Framework - lafProcessData
# Copyright (c) 2019 IOActive Inc.  All rights reserved.

import argparse, sys, time, os, datetime as dt, traceback, logging as log, importlib, json
from db.Models import RowProcessed, Packet, commit, rollback
from utils import PolicyManager

# Define the number of raw packets that will be processed before writing into DB. It shoudn't be so big
BATCH_LENGTH =  64
REPORT_EVERY = 50

if os.environ.get("ENVIRONMENT") == "DEV":
    log.getLogger().setLevel(log.DEBUG)
else:
    log.getLogger().setLevel(log.INFO)

log.getLogger("pika").setLevel(log.WARNING)

policy_manager = PolicyManager()

ai_analyzer = None
base_analyzer = None
bruteforce_analyzer = None
LafPrinter = None

def processData():
    # Save the packet ids that have to be processed by the selected modules
    report_start_time = dt.datetime.now()
    report_start_packet_number = Packet.rows_quantity()
    report_last_print = 0

    starting_rows = list() 
    if options.analyze:
        analyzer_row = RowProcessed.find_one_by_analyzer("packet_analyzer")
        starting_rows.append(analyzer_row.last_row)

    if options.bforce:
        bruteforcer_row = RowProcessed.find_one_by_analyzer("bruteforcer")
        starting_rows.append(bruteforcer_row.last_row)

    if options.analyze_ia:
        ia_analyzer_row = RowProcessed.find_one_by_analyzer("ia_analyzer")
        starting_rows.append(ia_analyzer_row.last_row)

    # Get the lowest packet ID to be processed 
    first_pending_id=starting_rows[0]
    for row in starting_rows:
        if row < first_pending_id:
            first_pending_id = row

    # Jump to the next to be procesed
    first_pending_id += 1
    
    # If the user provided the start id, do some checks
    start_packet_id = None
    if options.from_id is not None:
        start_packet_id = options.from_id
        if start_packet_id > first_pending_id:
            print ("Warning! You are jumping over packets that weren't processed. Last packets ID processed: ")
            if options.bforce:
                print ("Bruteforcer: %d."%(bruteforcer_row.last_row))
            if options.analyze:
                print ("Analyzer: %d."%(analyzer_row.last_row ))
            if options.analyze_ia:
                print("IA analyzer: %d."%(ia_analyzer_row.last_row ))
        elif start_packet_id < first_pending_id: 
            print ("Warning! You will process twice some packets and duplicate information in DB. Last packets ID processed: ")
            if options.bforce:
                print ("Bruteforcer: %d."%(bruteforcer_row.last_row))
            if options.analyze:
                print ("Analyzer: %d."%(analyzer_row.last_row ))
            if options.analyze_ia:
                print("IA analyzer: %d."%(ia_analyzer_row.last_row ))
    else:    
        start_packet_id = first_pending_id

    # Start processing in batches
    keep_iterating = True
    while keep_iterating:
        session_packets = None

        number_of_packets = Packet.rows_quantity() or 0

        # Select the quantity of packets to process according to PACKES_BATCH and the limit that the user may have provided
        if options.to_id is None:
            if (start_packet_id + BATCH_LENGTH + 1) <= number_of_packets:
                session_packets = Packet.find_all_from(start_packet_id, BATCH_LENGTH)
                start_packet_id += BATCH_LENGTH

            else:
                time.sleep(5)
                continue
        else:
            if (start_packet_id + BATCH_LENGTH + 1) <= options.to_id:
                
                if (start_packet_id + BATCH_LENGTH) <= number_of_packets:
                    session_packets = Packet.find_all_from(start_packet_id, BATCH_LENGTH)
                    start_packet_id += BATCH_LENGTH

                else:
                    log.debug("No more packets to process. Sleeping a while")
                    time.sleep(5)
                    continue
            
            else:
                session_packets = Packet.find_all_from(start_packet_id, options.to_id - start_packet_id + 1)
                start_packet_id += (options.to_id % BATCH_LENGTH)
                keep_iterating = False

        if session_packets is not None:
            main_analyzer_last_row = RowProcessed.find_one_by_analyzer("packet_analyzer").last_row
            for packet in session_packets:
                # log.debug("Using packet: %d"%(packet.id))

                policy_manager.use_policy(packet.organization_id, packet.data_collector_id)
                # log.debug("Using policy: {name} ({id})".\
                    #format(name = policy_manager.active_policy.name,
                    #       id = policy_manager.active_policy.id))

                if options.bforce or options.analyze_ia:
                    while packet.id >= main_analyzer_last_row:
                        log.debug("Wait for main analyzer to instantiate objects. Sleeping a while.")
                        time.sleep(10)
                        main_analyzer_last_row = RowProcessed.find_one_by_analyzer("packet_analyzer").last_row

                try:
                    # If the starting packet wasn't given, check if the packet wasn't processed by each analyzer (except for the parser, which doesn't modify the DB)
                    if options.from_id is None:
                        if options.bforce and bruteforcer_row.last_row < packet.id:
                            bruteforce_analyzer.process_packet(packet, policy_manager)
                            bruteforcer_row.last_row = packet.id

                        if options.analyze and analyzer_row.last_row  < packet.id:
                            base_analyzer.process_packet(packet, policy_manager)
                            analyzer_row.last_row = packet.id

                        if options.analyze_ia and ia_analyzer_row.last_row < packet.id:
                            ai_analyzer.process_packet(packet, policy_manager)
                            ia_analyzer_row.last_row = packet.id

                    # If the starting packet was given by the user, don't do any check
                    else:
                        if options.bforce:
                            bruteforce_analyzer.process_packet(packet, policy_manager)
                            if bruteforcer_row.last_row < packet.id:
                                bruteforcer_row.last_row = packet.id

                        if options.analyze:
                            base_analyzer.process_packet(packet, policy_manager)
                            if analyzer_row.last_row  < packet.id:
                                analyzer_row.last_row = packet.id

                        if options.analyze_ia:
                            ai_analyzer.process_packet(packet, policy_manager)
                            if ia_analyzer_row.last_row  < packet.id:
                                ia_analyzer_row.last_row = packet.id
                            
                except Exception as e:
                    log.error("Error processing packet {0}. Exception: {1}".format(packet.id ,e))
                    traceback.print_exc()
                    rollback()

                if options.parse:
                    LafPrinter.printPacket(packet)

                # Commit objects in DB before starting with the next packet
                try:
                    commit()
                except Exception as exc:
                    rollback()
                    log.error("Error trying to commit after packet processing finish: {0}".format(exc))
                
            if options.report_stats:
                if report_last_print >= REPORT_EVERY:
                    packet_row_quantity = Packet.rows_quantity()

                    batch_time = dt.datetime.now() - report_start_time
                    new_packets_db = (packet_row_quantity - report_start_packet_number) 
                    processed_per_minute = int(60 * REPORT_EVERY * BATCH_LENGTH / batch_time.seconds)
                    packet_table_growth = int(60 * new_packets_db / batch_time.seconds)
                    log.info(f"Processed {processed_per_minute} per minute. " \
                            f"Packet table grows at {packet_table_growth} per minute.")

                    report_start_time = dt.datetime.now()
                    report_start_packet_number = packet_row_quantity
                    report_last_print = 0
                else:
                    report_last_print += 1

def import_analyzers():
    if options.parse:
        try:
            global LafPrinter
            LafPrinter = importlib.import_module("analyzers.printer.LafPrinter")
            log.debug("DataParser module ON")
        except ImportError:
            log.error("Parser module not available")

    if options.bforce:
        try:
            global bruteforce_analyzer
            bruteforce_analyzer = importlib.import_module("analyzers.rolaguard_bruteforce_analyzer")
            log.debug("Bruteforce module ON")
            if options.keys is not None:
                log.debug("- Using keys file: %s"%(options.keys))
                keysPath = options.keys
            if options.no_gen is True:
                log.debug("- Keys won't be generated dinamically by bruteforcer")
            if options.hours>0:
                print ("- Will wait {0} hours between bruteforces for each device".format(options.hours))
            bruteforce_analyzer.init(keysPath, options.no_gen, options.hours)
        except ImportError as e:
            log.error(f"Error loading bruteforcer module: {e}")
            exit(1)
    else:
        if options.keys is not None or options.no_gen is not None:
            log.debug("Bruteforce module OFF - Won't accept its suboptions")

    if options.analyze_ia:
        try:
            global ai_analyzer
            ai_analyzer = importlib.import_module("analyzers.rolaguard_ai_analyzer")
            log.debug("IA analyzer module ON")
        except ImportError as e:
            log.error(f"Error loading AI module: {e}")
            exit(1)

    if options.analyze:
        try:
            global base_analyzer
            base_analyzer = importlib.import_module("analyzers.rolaguard_base_analyzer")
            log.debug("Analyzer module ON")
        except ImportError as e:
            log.error(f"Error loading base module: {e}")
            exit(1)

    print ("\n********************************************\n")



if __name__ == '__main__':
    try:
        print ("\n*****************************************************")
        print ("LoRaWAN Security Framework - %s"%(sys.argv[0]))
        print ("Copyright (c) 2019 IOActive Inc.  All rights reserved.")
        print ("*****************************************************\n")
        print ("*****************************************************\n")
        parser = argparse.ArgumentParser(description='This script reads retrieves packets from DB and executes different sub-tools. ' \
                                                     'Then, each sub-tool will save output data into the DB. ' \
                                                     'See each option for more information.')
        parser.add_argument("-a", "--analyze",
                            help = "Collect and analyze different aspects from traffic. If Bruteforcer (-b) is activated, results will be corelated",
                            action="store_true",
                            default = False
                            )
        parser.add_argument("-i", "--analyze-ia",
                            help = "Perform checks using artificial intelligence methods such as frequency checks, devices fingerprint, etc",
                            action="store_true",
                            default = False
                            )
        parser.add_argument("-b", "--bforce",
                            help = "Try to bruteforce the AppKeys with JoinRequests and JoinAccepts payloads",
                            action="store_true",
                            default = False
                            )
        parser.add_argument("-k", "--keys", 
                            help = '[Bruteforcer] Filepath to keys file.  If not provided, "keys.txt" will be used',
                            default = "./analyzers/rolaguard_bruteforce_analyzer/keys.txt"
                            )
        parser.add_argument("--no-gen",
                            help = "[Bruteforcer] Don't generate keys, only try keys from files",
                            action = 'store_true',
                            default = None
                            )
        parser.add_argument("--hours",
                            help = "[Bruteforcer] Hours between bruteforcing for each device.",
                            default = 24,
                            type = int
                            )
        parser.add_argument("-p", "--parse",
                            help= 'Parse the PHYPayload into readable information',
                            action="store_true", 
                            default=False
                            )
        parser.add_argument("--from-id",
                            help= 'Packet ID from where to start processing.',
                            default = None,
                            type = int
                            )
        parser.add_argument("--to-id",
                            help= 'Last packet ID to be processed.',
                            default = None,
                            type = int
                            )
        parser.add_argument("--report-stats",
                            help= 'Print number of packets processed per minute.',
                            action="store_true",
                            default = False
                            )

        options = parser.parse_args()

        # Parse args and init analyzers
        import_analyzers()

        policy_manager.subscribe_to_events()

        processData()
    
    except KeyboardInterrupt:
        print('exiting engine')
        exit(0)
