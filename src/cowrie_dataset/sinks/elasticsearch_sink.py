"""
Elasticsearch sink for storing session documents.

This handles:
  - Connection to ES (with optional auth)
  - Index creation with proper mappings
  - Bulk indexing of session documents
  - Upsert behavior (re-running won't create duplicates)

The index mapping is carefully designed to:
  - Use appropriate types (keyword vs text, ip, date, etc.)
  - Support efficient filtering and aggregations
  - Allow for future schema evolution

For MVP, we use a single index. For production, you might want:
  - Time-based indices (cowrie-sessions-2021.01)
  - Index lifecycle management (ILM)
  - Index templates
"""

import logging
from typing import Any, Iterator, Optional
from datetime import datetime

logger = logging.getLogger(__name__)

# Try to import elasticsearch - fail gracefully if not installed
try:
    from elasticsearch import Elasticsearch
    from elasticsearch.helpers import bulk, BulkIndexError
    ES_AVAILABLE = True
except ImportError:
    ES_AVAILABLE = False
    logger.warning("elasticsearch library not installed - ES sink will be disabled")


# Index mapping for session documents
SESSION_INDEX_MAPPING = {
    "settings": {
        "number_of_shards": 1,
        "number_of_replicas": 0,
        "refresh_interval": "5s",
    },
    "mappings": {
        "properties": {
            "session_id": {"type": "keyword"},
            "location": {"type": "keyword"},
            
            "connection": {
                "properties": {
                    "src_ip": {"type": "ip"},
                    "src_port": {"type": "integer"},
                    "dst_ip": {"type": "keyword"},  # might not be valid IP format
                    "dst_port": {"type": "integer"},
                    "protocol": {"type": "integer"},
                }
            },
            
            "timing": {
                "properties": {
                    "start_ts": {"type": "date"},
                    "end_ts": {"type": "date"},
                    "duration_s": {"type": "float"},
                }
            },
            
            "client": {
                "properties": {
                    "ssh_version": {"type": "keyword"},
                    "hassh": {"type": "keyword"},
                    "hassh_algorithms": {"type": "text"},
                }
            },
            
            "authentication": {
                "properties": {
                    "attempts": {"type": "integer"},
                    "success": {"type": "boolean"},
                    "failed_count": {"type": "integer"},
                    "success_count": {"type": "integer"},
                    "usernames_tried": {"type": "keyword"},
                    "final_username": {"type": "keyword"},
                    "final_password": {"type": "keyword"},
                }
            },
            
            "commands": {
                "properties": {
                    "total_count": {"type": "integer"},
                    "success_count": {"type": "integer"},
                    "failed_count": {"type": "integer"},
                    "inputs": {"type": "text"},
                    "unique_commands": {"type": "integer"},
                }
            },
            
            "downloads": {
                "properties": {
                    "count": {"type": "integer"},
                    "urls": {"type": "keyword"},
                    "shasums": {"type": "keyword"},
                }
            },
            
            "uploads": {
                "properties": {
                    "count": {"type": "integer"},
                }
            },
            
            "tcpip_forwards": {
                "properties": {
                    "count": {"type": "integer"},
                }
            },
            
            "features": {
                "type": "object",
                "enabled": True,
            },
            
            # Statistical Anomaly Detection
            "statistical_anomaly": {
                "type": "object",
                "properties": {
                    "is_anomaly": {"type": "boolean"},
                    "score": {"type": "float"},
                    "reasons": {"type": "keyword"},
                    "z_scores": {
                        "type": "object",
                        "dynamic": True
                    }
                }
            },
            
            # Pipeline A Output - Rule Based
            "labels_rule_based": {
                "properties": {
                    "level": {"type": "integer"},
                    "primary_tactic": {"type": "keyword"},
                    "all_tactics": {"type": "keyword"},
                    "matched_patterns": {"type": "keyword"},
                    "session_type": {"type": "keyword"},
                }
            },
            
            # Pipeline B Output - Agentic
            "labels_agentic": {
                "type": "object",
                "properties": {
                    "skipped": {"type": "boolean"},
                    "was_anomaly": {"type": "boolean"},
                    "hunter_verdict": {"type": "keyword"},
                    "hunter_confidence": {"type": "float"},
                    "hunter_reasoning": {"type": "text"},
                    "analyst_verdict": {
                        "type": "object",
                        "properties": {
                            "level": {"type": "integer"},
                            "primary_tactic": {"type": "keyword"},
                            "all_tactics": {"type": "keyword"},
                            "technique_ids": {"type": "keyword"},
                            "sophistication": {"type": "keyword"},
                            "intent": {"type": "text"},
                            "reasoning": {"type": "text"},
                            "confidence": {"type": "float"},
                            "iocs": {"type": "keyword"}
                        }
                    },
                    "pipeline_metrics": {
                        "type": "object",
                        "properties": {
                            "sent_to_hunter": {"type": "boolean"},
                            "sent_to_analyst": {"type": "boolean"},
                            "total_latency_ms": {"type": "integer"},
                            "total_cost_usd": {"type": "float"}
                        }
                    },
                    "error": {"type": "text"},
                    "stage": {"type": "keyword"}
                }
            },
            
            # Comparison Flags (computed during indexing)
            "label_comparison": {
                "type": "object",
                "properties": {
                    "tactics_agree": {"type": "boolean"},
                    "levels_agree": {"type": "boolean"},
                    "rule_level": {"type": "integer"},
                    "agent_level": {"type": "integer"},
                    "level_difference": {"type": "integer"}
                }
            },
            
            "geo": {
                "properties": {
                    "continent_code": {"type": "keyword"},
                    "country_name": {"type": "keyword"},
                    "country_iso": {"type": "keyword"},
                    "region_name": {"type": "keyword"},
                    "city_name": {"type": "keyword"},
                    "longitude": {"type": "float"},
                    "latitude": {"type": "float"},
                    "timezone": {"type": "keyword"},
                    "accuracy_radius": {"type": "integer"},
                }
            },
            
            "meta": {
                "properties": {
                    "event_count": {"type": "integer"},
                    "source_files": {"type": "keyword"},
                    "is_closed": {"type": "boolean"},
                    "session_type": {"type": "keyword"},
                    "ingested_at": {"type": "date"},
                }
            },
        }
    }
}


class ElasticsearchSink:
    """
    Sink for writing session documents to Elasticsearch.
    
    Usage:
        sink = ElasticsearchSink(
            host="http://localhost:9200",
            index_name="cowrie-sessions"
        )
        
        # Create the index (do this once)
        sink.create_index()
        
        # Index documents
        for session_doc in sessions:
            sink.add(session_doc)
        
        # Flush any remaining documents
        sink.flush()
        
        # Or use as context manager
        with ElasticsearchSink(...) as sink:
            for doc in docs:
                sink.add(doc)
        # auto-flushes on exit
    """
    
    def __init__(
        self,
        host: str = "http://localhost:9200",
        username: Optional[str] = None,
        password: Optional[str] = None,
        index_name: str = "cowrie-sessions",
        bulk_size: int = 500,
    ):
        """
        Args:
            host: Elasticsearch URL (include http:// or https://)
            username: Optional username for auth
            password: Optional password for auth
            index_name: Name of the index to write to
            bulk_size: Number of documents to buffer before bulk indexing
        """
        if not ES_AVAILABLE:
            raise RuntimeError("elasticsearch library not installed")
        
        self.host = host
        self.index_name = index_name
        self.bulk_size = bulk_size
        
        # Build connection kwargs
        es_kwargs = {"hosts": [host]}
        if username and password:
            es_kwargs["basic_auth"] = (username, password)
        
        # Disable SSL verification warnings for self-signed certs (dev only!)
        es_kwargs["verify_certs"] = False
        
        self._client = Elasticsearch(**es_kwargs)
        self._buffer = []
        self._indexed_count = 0
        self._error_count = 0
        
        logger.info(f"Connected to Elasticsearch at {host}")
    
    def create_index(self, delete_existing: bool = False) -> bool:
        """
        Create the session index with proper mappings.
        
        Args:
            delete_existing: If True, delete the index if it exists.
                           Use with caution - this destroys data!
        
        Returns True if index was created, False if it already existed.
        """
        if delete_existing and self._client.indices.exists(index=self.index_name):
            logger.warning(f"Deleting existing index: {self.index_name}")
            self._client.indices.delete(index=self.index_name)
        
        if self._client.indices.exists(index=self.index_name):
            logger.info(f"Index {self.index_name} already exists")
            return False
        
        logger.info(f"Creating index {self.index_name}")
        self._client.indices.create(
            index=self.index_name,
            body=SESSION_INDEX_MAPPING,
        )
        return True
    
    def add(self, doc: dict[str, Any]) -> None:
        """
        Add a document to the buffer.
        
        When the buffer reaches bulk_size, documents are automatically
        indexed. Call flush() at the end to index remaining documents.
        """
        # Add ingestion timestamp
        doc.setdefault("meta", {})["ingested_at"] = datetime.utcnow().isoformat()
        
        self._buffer.append(doc)
        
        if len(self._buffer) >= self.bulk_size:
            self._flush_buffer()
    
    def flush(self) -> None:
        """Flush any remaining documents in the buffer."""
        if self._buffer:
            self._flush_buffer()
    
    def _flush_buffer(self) -> None:
        """Internal method to bulk index the buffer."""
        if not self._buffer:
            return
        
        # Prepare bulk actions
        # We use index with _id=session_id for upsert behavior
        actions = []
        for doc in self._buffer:
            action = {
                "_index": self.index_name,
                "_id": doc.get("session_id", None),  # use session_id as doc ID
                "_source": doc,
            }
            actions.append(action)
        
        try:
            success, errors = bulk(
                self._client,
                actions,
                raise_on_error=False,
                raise_on_exception=False,
            )
            self._indexed_count += success
            
            if errors:
                self._error_count += len(errors)
                logger.warning(f"Bulk index had {len(errors)} errors")
                for error in errors[:5]:  # log first 5 errors
                    logger.debug(f"Bulk error: {error}")
            
            logger.debug(f"Indexed {success} documents (total: {self._indexed_count})")
            
        except Exception as e:
            logger.error(f"Bulk index failed: {e}")
            self._error_count += len(self._buffer)
        
        self._buffer.clear()
    
    def get_stats(self) -> dict[str, int]:
        """Return indexing statistics."""
        return {
            "indexed": self._indexed_count,
            "errors": self._error_count,
            "buffered": len(self._buffer),
        }
    
    def refresh(self) -> None:
        """Force a refresh so documents are immediately searchable."""
        self._client.indices.refresh(index=self.index_name)
    
    def close(self) -> None:
        """Flush and close the connection."""
        self.flush()
        self._client.close()
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()


class DryRunSink:
    """
    A fake sink that just prints documents for testing.
    
    Useful when you want to test the pipeline without ES running.
    """
    
    def __init__(self, print_docs: bool = False, max_print: int = 5):
        self.print_docs = print_docs
        self.max_print = max_print
        self.doc_count = 0
    
    def create_index(self, delete_existing: bool = False) -> bool:
        logger.info("[DRY RUN] Would create index")
        return True
    
    def add(self, doc: dict[str, Any]) -> None:
        self.doc_count += 1
        if self.print_docs and self.doc_count <= self.max_print:
            import json
            print(f"\n=== Document {self.doc_count} ===")
            print(json.dumps(doc, indent=2, default=str))
    
    def flush(self) -> None:
        logger.info(f"[DRY RUN] Would flush {self.doc_count} documents")
    
    def get_stats(self) -> dict[str, int]:
        return {"indexed": self.doc_count, "errors": 0, "buffered": 0}
    
    def refresh(self) -> None:
        pass
    
    def close(self) -> None:
        pass
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
