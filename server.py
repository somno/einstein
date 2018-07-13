from twisted.internet.protocol import DatagramProtocol
from twisted.internet import reactor
import socket
import packets
import vscapture

ASSOCIATION_REQUEST_MESSAGE = vscapture.aarq_msg

class EinsteinServer(DatagramProtocol):
    """
    Handles communication with a Philips IntelliVue

    Currently a demo implementation - listens for existence announcements,
    associates, and does a one-time data request.
    """

    def datagramReceived(self, data, (host, port)):
        print("Datagram received!")

        if port == packets.PORT_CONNECTION_INDICATION:
            self.handleConnectionIndication(data, (host, port))
        else:
            if data[0:2] == '\xe1\x00':  # PIPG-42
                self.handleProtocolMessage(data, (host, port))
            else:
                self.handleAssociationMessage(data, (host, port))


    def handleConnectionIndication(self, data, (host, port)):
        print("Received ConnectionIndication message, associating")
        ci = packets.ConnectIndication()
        ci.dissect(data)

        # TODO Store for later usage, don't just blindly
        self.transport.write(ASSOCIATION_REQUEST_MESSAGE, (host, packets.PORT_PROTOCOL))


    def handleAssociationMessage(self, data, (host, port)):
        print("Received Association message")
        associationMessage = packets.SessionHeader()
        associationMessage.dissect(data)
        associationMessage.show()
        # TODO Properly validate response, rejection, etc.


    def handleProtocolMessage(self, data, (host, port)):
        print("Received Protocol message, handling")
        message = packets.SPpdu()
        message.dissect(data)

        if packets.ROIVapdu in message:
            roivapdu = message[packets.ROIVapdu]

            if roivapdu.command_type == packets.CMD_CONFIRMED_EVENT_REPORT:
                print("Received MDSCreateEventReport, sending MDSCreateEventResult")

                # Ok! Now to reply!

                mdsceResult = packets.SPpdu()
                mdsceResult = mdsceResult / packets.ROapdus(ro_type=packets.RORS_APDU)
                mdsceResult = mdsceResult / packets.RORSapdu(
                    command_type=packets.CMD_CONFIRMED_EVENT_REPORT,
                    invoke_id=message[packets.ROIVapdu].invoke_id,
                )
                mdsceResult = mdsceResult / packets.EventReportResult(
                    managed_object=message[packets.EventReportArgument].managed_object,
                    event_type=packets.NOM_NOTI_MDS_CREAT,
                )

                self.transport.write(str(mdsceResult), (host, port))

                # And now follow up with a basic poll

                self.pollForData((host, port))
            else:
                print("Unknown command_type in roivapdu!")
                roivapdu.show()
        elif packets.ROLRSapdu in message:
            # TODO Implement support for rolling up Remote Operation Linked Results
            print("ROLRSapdu!")
            # message.show()
            self.displayResult(message)
        elif packets.ROERapdu in message:
            # Error
            message[packets.ROERapdu].show()
        elif packets.RORSapdu in message:
            print("Results!")
            # message.show()
            self.displayResult(message)
        else:
            print("Unknown message!")
            message.show()


    def pollForData(self, (host, port)):
        pollAction = packets.SPpdu()  # PIPG-55
        pollAction /= packets.ROapdus(ro_type=packets.ROIV_APDU)
        pollAction /= packets.ROIVapdu(command_type=packets.CMD_CONFIRMED_ACTION)
        pollAction /= packets.ActionArgument(
            managed_object=packets.ManagedObjectId(m_obj_class=packets.NOM_MOC_VMS_MDS),
            action_type=packets.NOM_ACT_POLL_MDIB_DATA,
        )
        pollAction /= packets.PollMdibDataReq(
            polled_obj_type=packets.TYPE(
                partition=packets.NOM_PART_OBJ,
                code=packets.NOM_MOC_VMO_METRIC_NU,  # Numerics, i.e. numbers about attached patient
            ),
            polled_attr_grp=packets.NOM_ATTR_GRP_METRIC_VAL_OBS,  # Observed values of the "object" (patient)
        )

        # pollAction.show2()

        self.transport.write(str(pollAction), (host, port))


    def displayResult(self, message):
        """
        This is quick and nasty and ignores all kinds of context, just focussing on ObservationPolls with data
        """

        poll_info_list = message[packets.PollInfoList]

        for single_context_poll in poll_info_list.value:
            for observation_poll in single_context_poll.value:
                for attribute_list in observation_poll.attributes:
                    for attribute in attribute_list.value:
                        if attribute.attribute_id == packets.NOM_ATTR_NU_VAL_OBS:
                            obsValue = attribute[packets.NuObsValue]
                            if obsValue.measurementIsValid():
                                obsValue.show()


reactor.listenUDP(packets.PORT_CONNECTION_INDICATION, EinsteinServer())
print("Starting...")
reactor.run()
