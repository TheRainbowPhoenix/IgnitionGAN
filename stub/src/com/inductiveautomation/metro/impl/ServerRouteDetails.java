package com.inductiveautomation.metro.impl;

import com.inductiveautomation.metro.api.ServerId;
import java.io.Serializable;

public class ServerRouteDetails implements Serializable, Comparable<ServerRouteDetails> {
    private static final long serialVersionUID = -150151089581073111L;

    private ServerId serverAddress;
    private int routeDistance;

    public ServerRouteDetails(ServerId serverAddress, int routeDistance) {
        this.serverAddress = serverAddress;
        this.routeDistance = routeDistance;
    }

    public ServerId getServerAddress() {
        return this.serverAddress;
    }

    public int getRouteDistance() {
        return this.routeDistance;
    }

    @Override
    public int compareTo(ServerRouteDetails other) {
        if (other == null) return 0;
        if (this.getServerAddress().equals(other.getServerAddress())) {
            return Integer.valueOf(this.routeDistance).compareTo(other.getRouteDistance());
        }
        return this.getServerAddress().getServerName().compareTo(other.getServerAddress().getServerName());
    }

    @Override
    public int hashCode() {
        int result = this.serverAddress.hashCode();
        result = 31 * result + this.routeDistance;
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (obj == null || !(obj instanceof ServerRouteDetails)) return false;
        ServerRouteDetails other = (ServerRouteDetails) obj;
        return this.serverAddress.equals(other.getServerAddress()) && this.routeDistance == other.getRouteDistance();
    }

    @Override
    public String toString() {
        return String.format("%s/%s", this.serverAddress, this.routeDistance);
    }
}
