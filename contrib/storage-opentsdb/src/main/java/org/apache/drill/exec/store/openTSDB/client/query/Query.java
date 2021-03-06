/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.drill.exec.store.openTSDB.client.query;

import java.util.Map;

/**
 * Query is an abstraction of openTSDB subQuery
 * and it is integral part of DBQuery
 * <p>
 * Each sub query can retrieve individual or groups of timeseries data,
 * performing aggregation on each set.
 */
public class Query {

  /**
   * The name of an aggregation function to use.
   */
  private String aggregator;
  /**
   * The name of a metric stored in the system
   */
  private String metric;
  /**
   * Whether or not the data should be converted into deltas before returning.
   * This is useful if the metric is a continuously incrementing counter
   * and you want to view the rate of change between data points.
   */
  private String rate;
  /**
   * An optional downsampling function to reduce the amount of data returned.
   */
  private String downsample;
  /**
   * To drill down to specific timeseries or group results by tag,
   * supply one or more map values in the same format as the query string.
   */
  private Map<String, String> tags;

  public String getAggregator() {
    return aggregator;
  }

  public void setAggregator(String aggregator) {
    this.aggregator = aggregator;
  }

  public String getMetric() {
    return metric;
  }

  public void setMetric(String metric) {
    this.metric = metric;
  }

  public String getRate() {
    return rate;
  }

  public void setRate(String rate) {
    this.rate = rate;
  }

  public String getDownsample() {
    return downsample;
  }

  public void setDownsample(String downsample) {
    this.downsample = downsample;
  }

  public Map<String, String> getTags() {
    return tags;
  }

  public void setTags(Map<String, String> tags) {
    this.tags = tags;
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }

    Query subQuery = (Query) o;

    if (aggregator != null ? !aggregator.equals(subQuery.aggregator) : subQuery.aggregator != null) {
      return false;
    }
    if (metric != null ? !metric.equals(subQuery.metric) : subQuery.metric != null) {
      return false;
    }
    if (rate != null ? !rate.equals(subQuery.rate) : subQuery.rate != null) {
      return false;
    }
    if (downsample != null ? !downsample.equals(subQuery.downsample) : subQuery.downsample != null) {
      return false;
    }
    return tags != null ? tags.equals(subQuery.tags) : subQuery.tags == null;
  }

  @Override
  public int hashCode() {
    int result = aggregator != null ? aggregator.hashCode() : 0;
    result = 31 * result + (metric != null ? metric.hashCode() : 0);
    result = 31 * result + (rate != null ? rate.hashCode() : 0);
    result = 31 * result + (downsample != null ? downsample.hashCode() : 0);
    result = 31 * result + (tags != null ? tags.hashCode() : 0);
    return result;
  }

  @Override
  public String toString() {
    return "SubQuery{" +
        "aggregator='" + aggregator + '\'' +
        ", metric='" + metric + '\'' +
        ", rate='" + rate + '\'' +
        ", downsample='" + downsample + '\'' +
        ", tags=" + tags +
        '}';
  }
}
