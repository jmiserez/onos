/*
 * Copyright 2015 Open Networking Laboratory
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.onosproject.virtualbng;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.Collections;
import java.util.List;

import org.onlab.packet.IpAddress;
import org.onlab.packet.IpPrefix;
import org.onlab.packet.MacAddress;

/**
 * Contains the configuration data for virtual BNG that has been read from a
 * JSON-formatted configuration file.
 */
public final class VbngConfiguration {

    private final List<IpPrefix> localPublicIpPrefixes;
    private final IpAddress nextHopIpAddress;
    private final MacAddress publicFacingMac;

    /**
     * Default constructor.
     */
    private VbngConfiguration() {
        localPublicIpPrefixes = null;
        nextHopIpAddress = null;
        publicFacingMac = null;
    }

    /**
     * Constructor.
     *
     * @param nextHopIpAddress the IP address of the next hop
     * @param prefixes the public IP prefix list for local SDN network
     * @param publicFacingMac the MAC address configured for all local
     *        public IP addresses
     */
    @JsonCreator
    public VbngConfiguration(@JsonProperty("localPublicIpPrefixes")
                             List<IpPrefix> prefixes,
                             @JsonProperty("nextHopIpAddress")
                             IpAddress nextHopIpAddress,
                             @JsonProperty("publicFacingMac")
                             MacAddress publicFacingMac) {
        localPublicIpPrefixes = prefixes;
        this.nextHopIpAddress = nextHopIpAddress;
        this.publicFacingMac = publicFacingMac;
    }

    /**
     * Gets a list of public IP prefixes configured for local SDN network.
     *
     * @return the list of public IP prefixes
     */
    public List<IpPrefix> getLocalPublicIpPrefixes() {
        return Collections.unmodifiableList(localPublicIpPrefixes);
    }

    /**
     * Gets the IP address configured for the next hop (upstream gateway).
     *
     * @return the IP address of the next hop
     */
    public IpAddress getNextHopIpAddress() {
        return nextHopIpAddress;
    }

    /**
     * Gets the MAC address configured for all the public IP addresses.
     *
     * @return the MAC address
     */
    public MacAddress getPublicFacingMac() {
        return publicFacingMac;
    }
}
