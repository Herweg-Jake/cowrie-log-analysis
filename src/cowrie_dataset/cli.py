"""
Command-line interface for the Cowrie dataset pipeline.

This is the main entry point for running the pipeline. It ties together
all the components: parsing, aggregation, feature extraction, labeling,
and storage.

Usage:
    # Process 10 files from Amsterdam (MVP test)
    python -m cowrie_dataset.cli --location ssh-amsterdam --limit 10

    # Process all files from all locations
    python -m cowrie_dataset.cli --all

    # Dry run (no ES, just print stats)
    python -m cowrie_dataset.cli --location ssh-amsterdam --limit 5 --dry-run
"""

import argparse
import logging
import sys
from pathlib import Path
from datetime import datetime

from .config import Settings
from .parsers import CowrieParser
from .aggregators import SessionAggregator
from .features import extract_message_features, extract_host_features, extract_geo_features, GeoEnricher
from .labeling import MitreLabeler
from .sinks.elasticsearch_sink import ElasticsearchSink, DryRunSink
from .export.session_exporter import export_sessions_to_jsonl, export_session


def setup_logging(verbose: bool = False):
    """Configure logging for the CLI."""
    level = logging.DEBUG if verbose else logging.INFO
    
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    
    # Quiet down some noisy loggers
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("elasticsearch").setLevel(logging.WARNING)


def process_location(
    location: str,
    settings: Settings,
    sink,
    geo_enricher: GeoEnricher | None,
    limit: int | None = None,
) -> dict:
    """
    Process all files from a single honeypot location.
    
    Returns stats about what was processed.
    """
    logger = logging.getLogger(__name__)
    
    location_path = settings.get_location_path(location)
    logger.info(f"Processing location: {location} from {location_path}")
    
    if not location_path.exists():
        logger.error(f"Location path does not exist: {location_path}")
        return {"error": "path_not_found", "location": location}
    
    # Initialize components
    parser = CowrieParser()
    aggregator = SessionAggregator(location=location)
    labeler = MitreLabeler()
    
    # Process events
    sessions_processed = 0
    
    for event in parser.parse_directory(location_path, limit=limit, sort_by_date=True):
        # Add event to aggregator, get any completed sessions
        completed_sessions = aggregator.add_event(event)
        
        for session in completed_sessions:
            doc = build_session_document(session, labeler, geo_enricher)
            sink.add(doc)
            sessions_processed += 1
            
            if sessions_processed % 1000 == 0:
                logger.info(f"Processed {sessions_processed} sessions...")
    
    # Flush remaining sessions that never got a close event
    logger.info("Flushing incomplete sessions...")
    for session in aggregator.flush():
        doc = build_session_document(session, labeler, geo_enricher)
        sink.add(doc)
        sessions_processed += 1
    
    # Get stats
    parser_stats = parser.get_stats()
    aggregator_stats = aggregator.get_stats()
    
    return {
        "location": location,
        "files_parsed": parser_stats["files_parsed"],
        "events_parsed": parser_stats["events_parsed"],
        "parse_errors": parser_stats["errors"],
        "sessions_processed": sessions_processed,
    }


def build_session_document(
    session,
    labeler: MitreLabeler,
    geo_enricher: GeoEnricher | None,
) -> dict:
    """
    Build a complete session document ready for indexing.
    
    This combines the raw session data with extracted features and labels.
    """
    # Start with the base session data
    doc = session.to_dict()
    
    # Extract and add features
    message_features = extract_message_features(session)
    host_features = extract_host_features(session)
    geo_features = extract_geo_features(session, geo_enricher)
    
    # Combine all features into one dict
    doc["features"] = {
        **message_features,
        **host_features,
        **geo_features,
    }
    
    # Add geo data to top level too (for easier querying)
    doc["geo"] = {
        "continent_code": geo_features.get("F47_continent_code", ""),
        "country_name": geo_features.get("F48_country_name", ""),
        "country_iso": geo_features.get("F48_country_iso", ""),
        "region_name": geo_features.get("F49_region_name", ""),
        "city_name": geo_features.get("F50_city_name", ""),
        "longitude": geo_features.get("F51_longitude", 0.0),
        "latitude": geo_features.get("F52_latitude", 0.0),
        "timezone": geo_features.get("extra_timezone", ""),
        "accuracy_radius": geo_features.get("extra_accuracy_radius", 0),
    }
    
    # Apply labels (Pipeline A - rule-based)
    label = labeler.label(session)
    doc["labels_rule_based"] = label.to_dict()
    doc["labels_rule_based"]["session_type"] = session.get_session_type()
    
    return doc


def main():
    """Main entry point for the CLI."""
    parser = argparse.ArgumentParser(
        description="Process Cowrie honeypot logs into ML-ready datasets",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    
    parser.add_argument(
        "--location", "-l",
        help="Honeypot location to process (e.g., ssh-amsterdam)",
    )
    parser.add_argument(
        "--all", "-a",
        action="store_true",
        help="Process all configured locations",
    )
    parser.add_argument(
        "--limit", "-n",
        type=int,
        help="Limit number of files to process per location (for testing)",
    )
    parser.add_argument(
        "--dry-run", "-d",
        action="store_true",
        help="Don't write to ES, just print stats",
    )
    parser.add_argument(
        "--print-docs", "-p",
        action="store_true",
        help="Print sample documents (only with --dry-run)",
    )
    parser.add_argument(
        "--create-index", "-c",
        action="store_true",
        help="Create the ES index before processing",
    )
    parser.add_argument(
        "--delete-index",
        action="store_true",
        help="Delete existing index before creating (DANGER!)",
    )
    parser.add_argument(
        "--es-host",
        help="Elasticsearch host URL (overrides .env)",
    )
    parser.add_argument(
        "--data-dir",
        help="Honeypot data directory (overrides .env)",
    )
    parser.add_argument(
        "--export", "-e",
        help="Export sessions to JSONL file instead of Elasticsearch (path to output file)",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable debug logging",
    )
    
    args = parser.parse_args()
    
    # Setup logging
    setup_logging(args.verbose)
    logger = logging.getLogger(__name__)
    
    # Validate args
    if not args.location and not args.all:
        parser.error("Either --location or --all is required")
    
    # Load settings
    settings = Settings()
    
    # Override settings from args if provided
    if args.es_host:
        settings.es_host = args.es_host
    if args.data_dir:
        settings.honeypot_data_dir = Path(args.data_dir)
    
    # Determine which locations to process
    if args.all:
        locations = settings.locations
    else:
        locations = [args.location]
    
    logger.info(f"Will process locations: {locations}")
    
    # Initialize geo enricher (optional)
    geo_enricher = None
    if settings.geolite_db_path and settings.geolite_db_path.exists():
        try:
            geo_enricher = GeoEnricher(settings.geolite_db_path)
            logger.info("Geo enrichment enabled")
        except Exception as e:
            logger.warning(f"Failed to load GeoLite2: {e}")
    else:
        logger.info("Geo enrichment disabled (no GeoLite2 database)")
    
    # Check if we're exporting to JSONL instead of Elasticsearch
    if args.export:
        logger.info(f"EXPORT MODE - writing to {args.export}")
        export_path = Path(args.export)
        
        # Collect all sessions
        labeler = MitreLabeler()
        all_sessions = []
        
        start_time = datetime.now()
        
        for location in locations:
            location_path = settings.get_location_path(location)
            logger.info(f"Processing location: {location} from {location_path}")
            
            if not location_path.exists():
                logger.error(f"Location path does not exist: {location_path}")
                continue
            
            parser = CowrieParser()
            aggregator = SessionAggregator(location=location)
            
            for event in parser.parse_directory(location_path, limit=args.limit, sort_by_date=True):
                completed_sessions = aggregator.add_event(event)
                all_sessions.extend(completed_sessions)
            
            # Flush remaining sessions
            all_sessions.extend(aggregator.flush())
            
            logger.info(f"Collected {len(all_sessions)} sessions from {location}")
        
        # Export to JSONL
        logger.info(f"Exporting {len(all_sessions)} sessions to {export_path}...")
        count = export_sessions_to_jsonl(
            iter(all_sessions),
            export_path,
            geo_enricher,
            progress_callback=lambda n: logger.info(f"Exported {n} sessions...")
        )
        
        if geo_enricher:
            geo_enricher.close()
        
        elapsed = datetime.now() - start_time
        logger.info(f"\n{'='*60}")
        logger.info("EXPORT COMPLETE")
        logger.info(f"{'='*60}")
        logger.info(f"Time elapsed: {elapsed}")
        logger.info(f"Sessions exported: {count}")
        logger.info(f"Output file: {export_path}")
        logger.info(f"{'='*60}")
        return
    
    # Initialize sink
    if args.dry_run:
        sink = DryRunSink(print_docs=args.print_docs, max_print=5)
        logger.info("DRY RUN MODE - no data will be written to ES")
    else:
        sink = ElasticsearchSink(
            host=settings.es_host,
            username=settings.es_user,
            password=settings.es_password,
            index_name=settings.get_index_name(),
            bulk_size=settings.bulk_size,
        )
        
        if args.create_index:
            sink.create_index(delete_existing=args.delete_index)
    
    # Process each location
    start_time = datetime.now()
    all_stats = []
    
    try:
        for location in locations:
            stats = process_location(
                location=location,
                settings=settings,
                sink=sink,
                geo_enricher=geo_enricher,
                limit=args.limit,
            )
            all_stats.append(stats)
            logger.info(f"Location {location} stats: {stats}")
        
        # Final flush
        sink.flush()
        
        if not args.dry_run:
            sink.refresh()  # make docs searchable immediately
        
    finally:
        sink.close()
        if geo_enricher:
            geo_enricher.close()
    
    # Print summary
    elapsed = datetime.now() - start_time
    logger.info(f"\n{'='*60}")
    logger.info("PROCESSING COMPLETE")
    logger.info(f"{'='*60}")
    logger.info(f"Time elapsed: {elapsed}")
    logger.info(f"Sink stats: {sink.get_stats()}")
    
    for stats in all_stats:
        if "error" not in stats:
            logger.info(
                f"  {stats['location']}: "
                f"{stats['files_parsed']} files, "
                f"{stats['events_parsed']} events, "
                f"{stats['sessions_processed']} sessions"
            )
    
    logger.info(f"{'='*60}")


if __name__ == "__main__":
    main()
